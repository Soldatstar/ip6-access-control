"""
Supervisor module for managing system calls.

This module provides functionality to monitor and control system calls made by a child process.
It uses ptrace for syscall interception and ZeroMQ for communication with a decision-making server.
The module also supports seccomp for syscall filtering and shared lists for managing allowed and denied syscalls.
"""

import zmq
import json
from sys import stderr, argv, exit
from os import execv, path, kill, getpid
from signal import SIGKILL, SIGUSR1
from errno import EPERM
from multiprocessing import Manager, Process
from itertools import chain
from collections import Counter, namedtuple
import argparse

from ptrace.debugger import (
    PtraceDebugger, ProcessExit, NewProcessEvent, ProcessSignal)
from ptrace.func_call import FunctionCallOptions
from pyseccomp import SyscallFilter, ALLOW, TRAP, Arg, EQ

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
SYSCALL_ID_SET = set()

def init_seccomp(deny_list):
    """
    Initialize seccomp rules based on the deny list.

    Args:
        deny_list (list): A list of denied syscalls and their arguments.
    """
    sys_filter = SyscallFilter(defaction=ALLOW)

    for deny_decision in deny_list:
        syscall_nr = deny_decision[0]
        for i in range(len(deny_decision[1:])):
            try:
                # TODO: Look at seccomp how path to files are handled
                if not isinstance(deny_decision[1:][i], str):
                    sys_filter.add_rule(TRAP, syscall_nr, Arg(
                        i, EQ, deny_decision[1:][i]))
            except TypeError as e:
                LOGGER.warning("TypeError: %s - For syscall_nr: %s, Argument: %s",
                               e, syscall_nr, deny_decision[1:][i])

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
    socket.send_multipart([b'', json.dumps(message).encode()])
    while True:
        _, response = socket.recv_multipart()
        response_data = json.loads(response.decode())
        LOGGER.debug("Received response: %s", response_data)
        if response_data['status'] == "success":
            ALLOW_SET.clear()
            DENY_SET.clear()
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


def is_already_decided(syscall_nr, arguments):
    """
    Check if a decision has already been made for a syscall and its arguments.

    Args:
        syscall_nr (int): Number of the syscall.
        arguments (list): Arguments of the syscall.

    Returns:
        bool: True if the decision is already made, False otherwise.
    """
    key = tuple([syscall_nr] + arguments)
    # Fast O(1) check
    if key in ALLOW_SET or key in DENY_SET:
        return True
    # Wildcard support: check for any tuple with "*" in place of any argument
    # (e.g., (nr, "*", ...)), but only if needed
    for allow_key in ALLOW_SET.union(DENY_SET):
        if allow_key[0] == syscall_nr and len(allow_key) == len(key):
            if all(a == "*" or a == b for a, b in zip(allow_key[1:], key[1:])):
                return True
    return False


def prepare_arguments(syscall_args):
    """
    Prepare arguments for a syscall based on their type.

    Args:
        syscall_args (list): List of syscall argument objects.

    Returns:
        list: Prepared arguments.
    """
    arguments = []
    for arg in syscall_args:
        match arg.name:
            case "filename":
                arguments.append(arg.format())
            case "flags":
                arguments.append(arg.value)
            case "mode":
                arguments.append(arg.value)
            case _:
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
    state = event.process.syscall_state
    syscall = state.event(FunctionCallOptions())

    if syscall.result is None:
        syscall_number = syscall.syscall
        if syscall_number not in SYSCALL_ID_SET:
            LOGGER.debug("Skipping non blacklisted call: %s", syscall_number)
            process.syscall()
            return

        LOGGER.info("Syscall number: %s", syscall_number)
        syscall_args = prepare_arguments(syscall_args=syscall.arguments)
        syscall_args_formated = [arg.format() + f"[{arg.name}]" for arg in syscall.arguments]
        combined_tuple = tuple([syscall_number] + syscall_args)
        LOGGER.info("Catching new syscall: %s", syscall.format())

        if not is_already_decided(syscall_nr=syscall_number, arguments=syscall_args):
            decision = ask_for_permission_zmq(
                syscall_name=syscall.name,
                syscall_nr=syscall_number,
                arguments_raw=syscall_args,
                arguments_formated=syscall_args_formated,
                socket=socket
            )

            if decision["decision"] == "ALLOW":
                LOGGER.info("Decision: ALLOW Syscall: %s", syscall.format())
                size_before = len(SYSCALL_ID_SET)
                ALLOW_SET.add(combined_tuple)
                for sid in decision.get("allowed_ids", []):
                    SYSCALL_ID_SET.discard(sid)
                LOGGER.debug("Updated dynamic blacklist (SYSCALL_ID_SET): %s", SYSCALL_ID_SET)
                LOGGER.debug("Size of SYSCALL_ID_SET before: %d, after: %d", size_before, len(SYSCALL_ID_SET))
            if decision["decision"] == "DENY":
                LOGGER.info("Decision: DENY Syscall: %s", syscall.format())
                DENY_SET.add(combined_tuple)
                process.setreg('orig_rax', -EPERM)
                process.syscall()
                event.process.debugger.waitSyscall()
                process.setreg('rax', -EPERM)
        else:
            LOGGER.debug("Decision for syscall: %s was already decided", syscall.format())
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
    process = debugger.addProcess(pid=child.pid, is_attached=False)

    process.cont()
    event = process.waitSignals(SIGUSR1)
    process.syscall()

    running = True
    while running:
        try:
            event = debugger.waitSyscall()
            if isinstance(event, ProcessSignal):
                LOGGER.info("***SIGNAL***: %s", event.name)
                process.syscall()
                continue
            elif isinstance(event, NewProcessEvent):
                LOGGER.info("***CHILD-PROCESS***")
                # TODO: Observe the Child with the debugger
                subprocess = event.process
                subprocess.parent.syscall()
                continue
            elif isinstance(event, ProcessExit):
                LOGGER.info("***PROCESS-EXECUTED***")
                running = False
                break
            else:
                handle_syscall_event(event, process, socket)
        except KeyboardInterrupt:
            LOGGER.info("Exiting supervisor...")
            running = False
        except Exception as e:
            LOGGER.error("Exception in main loop: %s", e)
            running = False

    debugger.quit()
    child.join()
    socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supervisor Main")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args, unknown = parser.parse_known_args()

    import logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    LOGGER.setLevel(log_level)
    if args.debug:
        LOGGER.info("Debug mode is enabled. Logging level set to DEBUG.")

    # Pass through unknown args (e.g., program to supervise)
    sys.argv = [sys.argv[0]] + unknown
    main()
