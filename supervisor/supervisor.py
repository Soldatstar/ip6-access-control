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
from collections import Counter

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
# TODO: improve logging, add various log levels

PROGRAM_RELATIVE_PATH = None
PROGRAM_ABSOLUTE_PATH = None
MANAGER = Manager()
ALLOW_LIST = MANAGER.list()
DENY_LIST = MANAGER.list()


def init_seccomp(deny_list):
    """
    Initialize seccomp rules based on the deny list.

    Args:
        deny_list (list): A list of denied syscalls and their arguments.
    """
    f = SyscallFilter(defaction=ALLOW)

    for deny_decision in deny_list:
        syscall_nr = deny_decision[0]
        for i in range(len(deny_decision[1:])):
            try:
                # TODO: Look at seccomp how path to files are handled
                if not isinstance(deny_decision[1:][i], str):
                    f.add_rule(TRAP, syscall_nr, Arg(
                        i, EQ, deny_decision[1:][i]))
            except TypeError as e:
                LOGGER.info("TypeError: %s - For syscall_nr: %s, Argument: %s",
                            e, syscall_nr, deny_decision[1:][i])

    f.load()


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

        return response_data['data']['decision']


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
    Initialize the shared ALLOW_LIST and DENY_LIST from the database.

    Args:
        socket (zmq.Socket): ZeroMQ socket for communication.
    """
    global ALLOW_LIST, DENY_LIST
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

        if response_data['status'] == "success":
            for syscall in response_data['data']['allowed_syscalls']:
                syscall_number = syscall[0]
                syscall_args = syscall[1]
                combined_array = [syscall_number] + syscall_args
                ALLOW_LIST.append(combined_array)

            for syscall in response_data['data']['denied_syscalls']:
                syscall_number = syscall[0]
                syscall_args = syscall[1]
                combined_array = [syscall_number] + syscall_args
                DENY_LIST.append(combined_array)
            LOGGER.info("Shared list initialized successfully.")
            break
        elif response_data['status'] == "error":
            LOGGER.info("Error initializing shared list: %s", response_data['data'])
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
    for decision in chain(ALLOW_LIST, DENY_LIST):
        if decision[0] == syscall_nr:
            if Counter(decision[1:]) == Counter(arguments):
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


def main():
    """
    Main function to start the supervisor.

    This function sets up the environment, initializes shared lists, and starts the child process.
    It also monitors syscalls and communicates with the decision-making server.
    """
    if len(argv) < 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        LOGGER.info("Nutzung: %s program", argv[0])
        exit(1)
    LOGGER.info("Starting supervisor for %s", argv[1])
    set_program_path(relative_path=argv[1])
    socket = setup_zmq()
    init_shared_list(socket=socket)

    child = Process(target=child_prozess, args=(DENY_LIST, argv))
    debugger = PtraceDebugger()
    debugger.traceFork()
    child.start()
    process = debugger.addProcess(pid=child.pid, is_attached=False)

    process.cont()
    event = process.waitSignals(SIGUSR1)
    process.syscall()

    while True:
        try:
            event = debugger.waitSyscall()
            state = event.process.syscall_state
            syscall = state.event(FunctionCallOptions())

            if syscall.result is None:
                syscall_number = syscall.syscall
                syscall_args = prepare_arguments(syscall_args=syscall.arguments)
                syscall_args_formated = [arg.format() + f"[{arg.name}]" for arg in syscall.arguments]
                combined_array = [syscall_number] + syscall_args
                LOGGER.info("Catching new syscall: %s", 
                            syscall.format())

                if not is_already_decided(syscall_nr=syscall_number, arguments=syscall_args):
                    decision = ask_for_permission_zmq(
                        syscall_name=syscall.name,
                        syscall_nr=syscall_number,
                        arguments_raw=syscall_args,
                        arguments_formated=syscall_args_formated,
                        socket=socket
                    )

                    if decision == "ALLOW":
                        LOGGER.info("Decision: ALLOW Syscall: %s",
                                    syscall.format())
                        ALLOW_LIST.append(combined_array)

                    if decision == "DENY":
                        LOGGER.info("Decision: DENY Syscall: %s",
                                    syscall.format())
                        DENY_LIST.append(combined_array)
                        process.setreg('orig_rax', -EPERM)
                        process.syscall()
                        debugger.waitSyscall()
                        process.setreg('rax', -EPERM)
                else:
                    LOGGER.info("Decision for syscall: %s was already decided", 
                            syscall.format())

            process.syscall()

        except ProcessSignal as event:
            LOGGER.info("***SIGNAL***: %s", 
                            event.name)
            process.syscall()
            continue

        except NewProcessEvent as event:
            LOGGER.info("***CHILD-PROCESS***")
            # TODO: Observe the Child with the debugger
            subprocess = event.process
            subprocess.parent.syscall()
            continue

        except ProcessExit as event:
            LOGGER.info("***PROCESS-EXECUTED***")
            break

        except KeyboardInterrupt:
            LOGGER.info("Exiting supervisor...")
            break

    debugger.quit()
    child.join()
    MANAGER.shutdown()
    socket.close()


if __name__ == "__main__":
    main()
