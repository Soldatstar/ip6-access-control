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
from shared import logging_config

# Directories
BASE_DIR = Path(__file__).resolve().parent.parent / "process-supervisor"
LOGS_DIR = BASE_DIR / "logs"

# Ensure required directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)

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
    init_seccomp(deny_list=deny_list)
    kill(getpid(), SIGUSR1)
    execv(argv[1], [argv[1]]+argv[2:])


def setup_zmq() -> zmq.Socket:
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)
    socket.connect("tcp://localhost:5556")
    return socket


def ask_for_permission_zmq(syscall_name, syscall_nr, arguments_raw, arguments_formated, socket) -> str:
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
    global PROGRAM_RELATIVE_PATH, PROGRAM_ABSOLUTE_PATH
    PROGRAM_RELATIVE_PATH = relative_path
    PROGRAM_ABSOLUTE_PATH = path.abspath(PROGRAM_RELATIVE_PATH)


def init_shared_list(socket):
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
    for decision in chain(ALLOW_LIST, DENY_LIST):
        if decision[0] == syscall_nr:
            if Counter(decision[1:]) == Counter(arguments):
                return True
    return False


def prepare_arguments(syscall_args):
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
                syscall_args = prepare_arguments(
                    syscall_args=syscall.arguments)
                syscall_args_formated = [arg.format()
                                         for arg in syscall.arguments]
                combined_array = [syscall_number] + syscall_args

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

            process.syscall()

        except ProcessSignal as event:
            LOGGER.info("***SIGNAL***")
            event.display()
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
