"""
Supervisor module for managing system calls.

This module provides functionality to monitor and control system calls made by a child process.
It uses ptrace for syscall interception and ZeroMQ for communication with a decision-making server.
The module also supports seccomp for syscall filtering and shared lists for managing allowed and denied syscalls.
"""

import zmq
import traceback
import json
import time
from sys import stderr, argv, exit
from os import execv, path, kill, getpid
from signal import SIGKILL, SIGUSR1
from errno import EPERM
from multiprocessing import Manager, Process
from itertools import chain
from collections import Counter, namedtuple
import argparse
import logging
from ptrace.debugger import (
    PtraceDebugger, ProcessExit, NewProcessEvent, ProcessSignal)
from ptrace.func_call import FunctionCallOptions
from pyseccomp import SyscallFilter, ALLOW, ERRNO, Arg, EQ

# Add the parent directory to sys.path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from shared import logging_config, conf_utils

# Directories
POLICIES_DIR, LOGS_DIR, LOGGER = conf_utils.setup_directories("supervisor.log", "Supervisor")


# Configure logging
log_file_path = LOGS_DIR / "supervisor.log"
LOGGER = logging_config.configure_logging(log_file_path, "Supervisor")
LOGGER.propagate = False  # Prevent double logging

PROGRAM_RELATIVE_PATH = None
PROGRAM_ABSOLUTE_PATH = None

ALLOW_SET = set()  # Set of tuples: (syscall_nr, arg1, arg2, ...)
DENY_SET = set()
DENY_NO_SECCOMP = set()
SYSCALL_ID_SET = set()
SYSCALL_COUNT = 0


def init_seccomp(deny_list):
    """
    Initialize seccomp rules based on the deny list.

    Args:
        deny_list (list): A list of denied syscalls and their arguments.
    """
    sys_filter = SyscallFilter(defaction=ALLOW)

    for deny_decision in deny_list:
        syscall_nr = deny_decision[0]
        LOGGER.debug("Processing deny decision for syscall_nr: %s", syscall_nr)
        
        try:
            args = []
            no_str = True
            for i in range(len(deny_decision[1:])):
                if isinstance(deny_decision[1:][i], str):
                    if deny_decision[1:][i] == "*":
                        LOGGER.debug("Ignore parameter for seccomp rule syscall_nr: %s, argument: %s at position: %s",
                                 syscall_nr, deny_decision[1:][i], i)
                        continue
                    else: 
                        no_str = False
                        LOGGER.debug("Stop prepare rule because of string for syscall_nr: %s, argument: %s at position: %s",
                                 syscall_nr, deny_decision[1:][i], i)
                        break
                LOGGER.debug("Prepare rule with parameter for syscall_nr: %s, argument: %s at position: %s",
                                 syscall_nr, deny_decision[1:][i], i)
                args.append(Arg(i, EQ, deny_decision[1:][i]))
            if no_str:
                LOGGER.debug("Add rule for syscall_nr: %s, arguments: %s",
                                 syscall_nr, args)
                sys_filter.add_rule(ERRNO(EPERM), syscall_nr, *args)
        except TypeError as e:
                LOGGER.warning("TypeError: %s - For syscall_nr: %s, argument: %s at position: %s",
                               e, syscall_nr, deny_decision[1:][i], i)

    LOGGER.info("Seccomp filter initialized with deny list: %s", deny_list)
    # Load the seccomp filter
    LOGGER.info("Loading seccomp filter")
    sys_filter.load()


def child_prozess(deny_list, argv):
    """
    Start the child process with seccomp rules applied.

    Args:
        deny_list (list): A list of denied syscalls and their arguments.
        argv (list): Command-line arguments for the child process.
    """
    init_seccomp(deny_list=deny_list)
    kill(getpid(), SIGUSR1)
    execv(argv[1], [argv[1]]+argv[2:])


def setup_zmq() -> zmq.Socket:
    """
    Set up a ZeroMQ DEALER socket for communication.

    Returns:
        zmq.Socket: A configured ZeroMQ socket.
    """
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)
    socket.connect("tcp://localhost:5556")
    return socket


def ask_for_permission_zmq(syscall_name, syscall_nr, arguments_raw, arguments_formated, socket) -> str:
    """
    Request permission for a syscall via ZeroMQ.

    Args:
        syscall_name (str): Name of the syscall.
        syscall_nr (int): Number of the syscall.
        arguments_raw (list): Raw arguments of the syscall.
        arguments_formated (list): Formatted arguments of the syscall.
        socket (zmq.Socket): ZeroMQ socket for communication.

    Returns:
        str: Decision from the server ("ALLOW" or "DENY").
    """
    message = {
        "type": "req_decision",
        "body": {
            "program": PROGRAM_ABSOLUTE_PATH,
            "syscall_id": syscall_nr,
            "syscall_name": syscall_name,
            "parameter_raw": arguments_raw,
            "parameter_formated": arguments_formated
        }
    }
    LOGGER.info("Asking for permission for syscall: %s", syscall_name)
    socket.send_multipart([b'', json.dumps(message).encode()])
    while True:
        _, response = socket.recv_multipart()
        response_data = json.loads(response.decode())
        LOGGER.debug("Received response: %s", response_data)
        return response_data['data']


def set_program_path(relative_path):
    """
    Set the relative and absolute paths of the program being supervised.

    Args:
        relative_path (str): Relative path to the program.
    """
    global PROGRAM_RELATIVE_PATH, PROGRAM_ABSOLUTE_PATH
    PROGRAM_RELATIVE_PATH = relative_path
    PROGRAM_ABSOLUTE_PATH = path.abspath(PROGRAM_RELATIVE_PATH)


def init_shared_list(socket):
    """
    Initialize the shared ALLOW_SET and DENY_SET from the database.

    Args:
        socket (zmq.Socket): ZeroMQ socket for communication.
    """
    global ALLOW_SET, DENY_SET, SYSCALL_ID_SET
    message = {
        "type": "read_db",
        "body": {
            "program": PROGRAM_ABSOLUTE_PATH
        }
    }
    LOGGER.info("Initializing shared list with program path: %s", PROGRAM_ABSOLUTE_PATH)
    LOGGER.debug("Sending message to user tool: %s", message)
    socket.send_multipart([b'', json.dumps(message).encode()])
    while True:
        _, response = socket.recv_multipart()
        response_data = json.loads(response.decode())
        LOGGER.debug("Received response: %s", response_data)
        LOGGER.info("Response status: %s", response_data['status'])
        if response_data['status'] == "success":
            ALLOW_SET.clear()
            DENY_SET.clear()
            DENY_NO_SECCOMP.clear()
            SYSCALL_ID_SET.clear()
            for syscall in response_data['data']['allowed_syscalls']:
                syscall_number = syscall[0]
                syscall_args = syscall[1]
                ALLOW_SET.add(tuple([syscall_number] + syscall_args))
            for syscall in response_data['data']['denied_syscalls']:
                syscall_number = syscall[0]
                syscall_args = syscall[1]
                DENY_SET.add(tuple([syscall_number] + syscall_args))
            rules = response_data['data']['blacklisted_ids']
            for syscall_id in rules:
                SYSCALL_ID_SET.add(syscall_id)
            LOGGER.info("Shared list initialized successfully.")
            LOGGER.debug("ALLOW_SET: %s", ALLOW_SET)
            LOGGER.debug("DENY_SET: %s", DENY_SET)
            LOGGER.debug("Dynamic blacklist (SYSCALL_ID_SET): %s", SYSCALL_ID_SET)
            break
        elif response_data['status'] == "error":
            LOGGER.error("Error initializing shared list: %s", response_data['data'])
            break


def check_decision_made(syscall_nr, arguments):
    """
    Check if a decision has already been made for a syscall and its arguments.

    Args:
        syscall_nr (int): Number of the syscall.
        arguments (list): Arguments of the syscall.

    Returns:
        tuple: (bool, bool) - The first bool indicates if the allow decision is already made, 
                              the second bool indicates if the deny decision is already made
    """
    key = tuple([syscall_nr] + arguments)
    # Fast O(1) check
    if key in ALLOW_SET:
        return True, False

    if key in DENY_SET:
        return False, True

    # Wildcard support: check for any tuple with "*" in place of any argument
    # (e.g., (nr, "*", ...)), but only if needed
    for allow_key in ALLOW_SET:
        if allow_key[0] == syscall_nr and len(allow_key) == len(key):
            if all(a == "*" or a == b for a, b in zip(allow_key[1:], key[1:])):
                return True, False
    
    for deny_key in DENY_SET:
        if deny_key[0] == syscall_nr and len(deny_key) == len(key):
            if all(a == "*" or a == b for a, b in zip(deny_key[1:], key[1:])):
                return False, True

    return False, False

def prepare_arguments(syscall_args):
    """
    Prepare arguments for a syscall based on their type.

    Args:
        syscall_args (list): List of syscall argument objects.

    Returns:
        list: Prepared arguments.
    """
    def is_hex(s: str) -> bool:
        if s.startswith(("0x", "0X")):
            s = s[2:]
        
        if not s:
            return False
        
        hex_digits = set("0123456789abcdefABCDEF")
        return all(c in hex_digits for c in s)

    arguments = []
    for arg in syscall_args:
        formatted = arg.format()
        if any(not char.isdigit() for char in formatted) and not is_hex(formatted):
            match arg.name:
                case "filename" | "pathname" | "oldname" | "old" | "path":
                    arguments.append(formatted)
                case "flags" | "domain" | "type":
                    arguments.append(arg.value)
                case _:
                    arguments.append("*")
        else: 
            arguments.append("*")
    return arguments

def handle_syscall_event(event, process, socket):
    """
    Handle a syscall event: check, log, and ask for permission if needed.

    Args:
        event: The syscall event to handle.
        process: The process being traced.
        socket: The ZeroMQ socket for communication.
    """

    global SYSCALL_COUNT
    SYSCALL_COUNT += 1
    state = event.process.syscall_state
    syscall = state.event(FunctionCallOptions())

    if syscall.result is None:
        syscall_number = syscall.syscall
        syscall_name = syscall.name

        LOGGER.info("Syscall number: %s", syscall_number)
        syscall_args = prepare_arguments(syscall_args=syscall.arguments)
        syscall_args_formated = [arg.format() + f"[{arg.name}]" for arg in syscall.arguments]
        combined_tuple = tuple([syscall_number] + syscall_args)
        LOGGER.info("Catching new syscall: %s PID: %d", syscall.format(), process.pid)
        decided_to_allow, decided_to_deny = check_decision_made(syscall_nr=syscall_number, arguments=syscall_args)

        if not decided_to_deny and syscall_number not in SYSCALL_ID_SET:
            LOGGER.debug("Skipping non blacklisted call: %s %s", syscall_number, syscall_name)
            process.syscall()
            return

        if not decided_to_allow and not decided_to_deny:
            decision = ask_for_permission_zmq(
                syscall_name=syscall_name,
                syscall_nr=syscall_number,
                arguments_raw=syscall_args,
                arguments_formated=syscall_args_formated,
                socket=socket
            )
            if decision["decision"] == "ALLOW":
                LOGGER.info("Decision: ALLOW(group) Syscall: %s", syscall.format())
                size_before = len(SYSCALL_ID_SET)
                for sid in decision.get("allowed_ids", []):
                    SYSCALL_ID_SET.discard(sid)
                LOGGER.debug("Updated dynamic blacklist (SYSCALL_ID_SET): %s", SYSCALL_ID_SET)
                LOGGER.debug("Size of SYSCALL_ID_SET before: %d, after: %d", size_before, len(SYSCALL_ID_SET))

            if decision["decision"] == "ALLOW_THIS":
                LOGGER.info("Decision: ALLOW_THIS Syscall: %s", syscall.format())
                LOGGER.debug("Updated ALLOW set with: %s", combined_tuple)
                ALLOW_SET.add(combined_tuple)
                
            if decision["decision"] == "DENY":
                LOGGER.debug("Updated DENY set with: %s", combined_tuple)
                DENY_SET.add(combined_tuple)
                DENY_NO_SECCOMP.add(combined_tuple)
                LOGGER.debug("DENY set after update: %s", DENY_SET)
                LOGGER.debug("DENY_NO_SECCOMP set after update: %s", DENY_NO_SECCOMP)
                LOGGER.info("Decision: DENY Syscall: %s", syscall.format())
                process.setreg('orig_rax', -EPERM)
                process.setreg('rax', -EPERM)
        elif decided_to_deny:
            no_seccomp = False

            if combined_tuple in DENY_NO_SECCOMP:
                no_seccomp = True

            for deny_key in DENY_NO_SECCOMP:
                if deny_key[0] == syscall_number and len(deny_key) == len(combined_tuple):
                    if all(a == "*" or a == b for a, b in zip(deny_key[1:], combined_tuple[1:])):
                        no_seccomp = True

            if any(isinstance(arg, str) and arg != "*" for arg in syscall_args):
                no_seccomp = True
                
            if no_seccomp: 
                LOGGER.debug("Syscall: %s must be denied without seccomp", syscall_args)
                LOGGER.info("Decision: DENY Syscall: %s", syscall.format())
                process.setreg('orig_rax', -EPERM)
                process.setreg('rax', -EPERM)
            else:
                LOGGER.debug("Syscall %s will be denied by seccomp", syscall.format())
        else:
            LOGGER.debug("Syscall %s was already allowed", syscall.format())
    process.syscall()



def main():
    """
    Main function to start the supervisor.

    This function sets up the environment, initializes shared lists, and starts the child process.
    It also monitors syscalls and communicates with the decision-making server.
    """
    if len(argv) < 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        LOGGER.error("Nutzung: %s program", argv[0])
        exit(1)

    LOGGER.info("Starting supervisor for %s", argv[1])
    set_program_path(relative_path=argv[1])
    socket = setup_zmq()
    init_shared_list(socket=socket)

    child = Process(target=child_prozess, args=(DENY_SET, argv))
    debugger = PtraceDebugger()
    debugger.traceFork()
    child.start()
    LOGGER.debug("Starting monitor process with deny list: %s", DENY_SET)

    process = debugger.addProcess(pid=child.pid, is_attached=False)

    # Wait for child to exec and raise SIGUSR1
    process.cont()
    event = process.waitSignals(SIGUSR1)
    process.syscall()
    
    # Start timing the child execution
    start_time = time.time()
    LOGGER.info("Monitor process execution started at %s", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)))
    LOGGER.debug("Starting main loop to monitor syscalls")
    
    while debugger:
        try:
             # This will either return a syscall event or raise ProcessSignal/NewProcessEvent/ProcessExit
             event = debugger.waitSyscall()

             # If it's genuinely a syscall event, handle it:
             handle_syscall_event(event, event.process, socket)

        except ProcessSignal as sig:
             # SIGTRAP from ptrace/seccomp → advance child
             LOGGER.debug("***SIGNAL*** %s PID: %d", sig.name, sig.process.pid)
             sig.process.syscall()
             continue

        except NewProcessEvent as newproc:
            # A child fork/exec’d: re‐attach and advance
            process_child = newproc.process
            LOGGER.info("***CHILD-PROCESS*** PID: %d", process_child.pid)
            process_child.syscall()
            newproc.process.parent.syscall()
            continue

        except ProcessExit as exitproc:
            # A process terminate
            LOGGER.info("***PROCESS-EXECUTED*** PID: %d", exitproc.process.pid)
            continue

        except KeyboardInterrupt:
             # Record end time for interrupted execution
             end_time = time.time()
             execution_duration = end_time - start_time
             LOGGER.info("Exiting supervisor...")
             LOGGER.info("Monitor process execution interrupted after %.3f seconds", execution_duration)
             break

        except Exception as e:
             # Record end time for error cases
             end_time = time.time()
             execution_duration = end_time - start_time
             LOGGER.error("Exception in main loop: %s", e)
             LOGGER.debug("Traceback: %s", traceback.format_exc())
             LOGGER.info("Monitor process execution stopped due to error after %.3f seconds", execution_duration)
             break
    
        end_time = time.time()
    execution_duration = end_time - start_time
    LOGGER.info("Monitor process execution ended at %s", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time)))
    
    LOGGER.error("Total execution time: %.3f ms", execution_duration * 1000)
    
    LOGGER.info("Performance metrics: %d syscalls processed", SYSCALL_COUNT)
    
    if execution_duration > 0:
        syscalls_per_sec = SYSCALL_COUNT / execution_duration
        LOGGER.error("Syscall processing rate: %.2f syscalls/sec", syscalls_per_sec)
        
    if SYSCALL_COUNT > 0:
        avg_time_per_syscall = (execution_duration * 1000) / SYSCALL_COUNT
        if avg_time_per_syscall >= 1.0:
            LOGGER.error("Average time per syscall: %.3f ms", avg_time_per_syscall)
        else:
            LOGGER.error("Average time per syscall: %.3f μs", avg_time_per_syscall * 1000)
            

    # Cleanup
    debugger.quit()
    child.join()
    socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supervisor Main")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--silent", action="store_true", help="Suppress all output except errors")
    args, unknown = parser.parse_known_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    if args.silent:
        log_level = logging.ERROR
    LOGGER.setLevel(log_level)
    for handler in LOGGER.handlers:
        handler.setLevel(log_level)
    if args.debug:
        LOGGER.info("Debug mode is enabled. Logging level set to DEBUG.")
        LOGGER.debug("Unknown arguments: %s", unknown)

    # Pass through unknown args (e.g., program to supervise)
    sys.argv = [sys.argv[0]] + unknown
    main()
