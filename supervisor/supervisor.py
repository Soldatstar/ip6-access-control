import zmq
import json
from sys import stderr, argv, exit
from os import execv, path, kill
from signal import SIGKILL
from multiprocessing import Manager, Process

from ptrace.debugger import (PtraceDebugger,ProcessExit,NewProcessEvent,ProcessSignal)
from ptrace.func_call import FunctionCallOptions
from pyseccomp import SyscallFilter, ALLOW, TRAP, Arg, EQ

PROGRAM_RELATIVE_PATH = None
PROGRAM_ABSOLUTE_PATH = None
MANAGER = Manager()
ALLOW_LIST = MANAGER.list()
DENY_LIST = MANAGER.list()

def init_seccomp(syscall_to_filter):
    f = SyscallFilter(defaction=ALLOW)
    
    for key in list(syscall_to_filter.keys()):
        for i in range(len(syscall_to_filter[key])):
            f.add_rule(TRAP, key, Arg(i, EQ, syscall_to_filter[key][i]))

    f.load()

def child_prozess(allow_list, deny_list, argv):
    # TODO: Give both lists to seccomp and adjust the filter
    init_seccomp(syscall_to_filter={})
    execv(argv[1],[argv[1]]+argv[2:])

def setup_zmq() -> zmq.Socket:
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)
    socket.connect("tcp://localhost:5556")
    return socket

def ask_for_permission_zmq(syscall, socket) -> str:
    message = {
        "type": "req_decision",
        "body": {
            "program": PROGRAM_ABSOLUTE_PATH,
            "syscall_id": syscall.syscall,
            "parameter": [arg.format() for arg in syscall.arguments]
        }
    }
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

            break    
        elif response_data['status'] == "error":
            break

def main():
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)

    set_program_path(relative_path=argv[1])
    socket = setup_zmq() 
    init_shared_list(socket=socket)

    child = Process(target=child_prozess, args=(ALLOW_LIST,DENY_LIST,argv))
    child.start()
    debugger = PtraceDebugger()
    debugger.traceFork()
    process = debugger.addProcess(pid=child.pid, is_attached=False)

    # TODO: Start once seccomp is set, because now also seccomp syscalls going to user-tool  
    process.syscall()
    
    while True:
        try: 
            event = debugger.waitSyscall()
            state = event.process.syscall_state
            syscall = state.event(FunctionCallOptions())
    
            if syscall.result is None:
                syscall_number = syscall.syscall
                syscall_args = [arg.format() for arg in syscall.arguments]
                combined_array = [syscall_number] + syscall_args
                
                # TODO: only ask if it's not in the ALLOW or DENY List
                decision = ask_for_permission_zmq(syscall=syscall, socket=socket)
                
                if decision == "ALLOW":
                    print(f"Decision: ALLOW, Prozess continues. Syscall: {syscall.format()}")
                    ALLOW_LIST.append(combined_array)
                    
                if decision == "DENY":
                    print(f"Decision: DENY, Prozess receives \"operation denied.\" Syscall: {syscall.format()}")
                    DENY_LIST.append(combined_array)
                    # TODO: Write into regs operation denied
                    kill(child.pid, SIGKILL)
                    break

            process.syscall()

        except ProcessSignal as event: 
            print(f"***SIGNAL***")
            event.display()
            process.syscall()
            continue

        except NewProcessEvent as event:
            print("***CHILD-PROCESS***")
            # TODO: Observe the Child with the debugger
            subprocess = event.process
            subprocess.parent.syscall()
            continue

        except ProcessExit as event:
            print("***PROCESS-EXECUTED***")
            break

        except KeyboardInterrupt:
            print("Exiting supervisor...")
            break 
    
    debugger.quit()
    child.join()
    MANAGER.shutdown() 
    socket.close()
    
    
if __name__ == "__main__":
    main()
