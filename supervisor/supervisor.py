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
import shutil  # Add this import
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
    # Use the resolved path that's already stored in PROGRAM_ABSOLUTE_PATH
    execv(PROGRAM_ABSOLUTE_PATH, [PROGRAM_ABSOLUTE_PATH]+argv[2:])


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


def set_program_path(relative_path):
    """
    Set the relative and absolute paths of the program being supervised.

    Args:
        relative_path (str): Relative path to the program.
    """
    global PROGRAM_RELATIVE_PATH, PROGRAM_ABSOLUTE_PATH
    PROGRAM_RELATIVE_PATH = relative_path
    PROGRAM_ABSOLUTE_PATH = path.abspath(relative_path)

def resolve_program_path(program_name):
    """
    Resolve a program name to its full path.
    
    If program_name is already an absolute path or a relative path with directory
    components, it is returned as-is. Otherwise, it's treated as a command name
    and resolved using PATH.
    
    Args:
        program_name (str): Program name or path
        
    Returns:
        str: Absolute path to the program or None if not found
    """
    # If it's already an absolute path or contains directory components
    if path.isabs(program_name) or '/' in program_name:
        return program_name
    
    # Otherwise, search in PATH
    full_path = shutil.which(program_name)
    if full_path:
        return full_path
    
    # If not found, return original (will likely fail later)
    return program_name


def main():
    """
    Main function to start the supervisor.

    This function sets up the environment, initializes shared lists, and starts the child process.
    It also monitors syscalls and communicates with the decision-making server.
    """
    # Parse arguments before anything else
    parser = argparse.ArgumentParser(description="Supervisor Main")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--silent", action="store_true", help="Suppress all output except errors")
    args, remaining_args = parser.parse_known_args()

    # Configure logging based on arguments
    log_level = logging.DEBUG if args.debug else logging.INFO
    if args.silent:
        log_level = logging.ERROR
    LOGGER.setLevel(log_level)
    for handler in LOGGER.handlers:
        handler.setLevel(log_level)
    if args.debug:
        LOGGER.info("Debug mode is enabled. Logging level set to DEBUG.")
        LOGGER.debug("Remaining arguments: %s", remaining_args)

    # Use remaining_args as program arguments
    if not remaining_args:
        print("Usage: %s program [args...]" % sys.argv[0], file=stderr)
        LOGGER.error("Usage: %s program [args...]", sys.argv[0])
        exit(1)

    # Resolve the program path first
    resolved_path = resolve_program_path(remaining_args[0])
    LOGGER.info("Starting supervisor for %s (resolved to %s)", remaining_args[0], resolved_path)
    
    # Replace the argument with the resolved path
    program_args = [resolved_path] + remaining_args[1:]
    
    set_program_path(relative_path=resolved_path)
    #socket = setup_zmq()
    #init_shared_list(socket=socket)

    child = Process(target=child_prozess, args=(DENY_SET, ["supervisor"] + program_args))
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
             event.process.syscall()  # Advance the process to the syscall state
             #handle_syscall_event(event, event.process, socket)

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
    #socket.close()


if __name__ == "__main__":
    main()
