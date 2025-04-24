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
SHARED_DICTINARY = MANAGER.dict()

def init_seccomp(syscall_to_filter):
    f = SyscallFilter(defaction=ALLOW)
    
    for key in list(syscall_to_filter.keys()):
        for i in range(len(syscall_to_filter[key])):
            f.add_rule(TRAP, key, Arg(i, EQ, syscall_to_filter[key][i]))

    f.load()

def child_prozess(shared_dict, argv):
    init_seccomp(syscall_to_filter=shared_dict)
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

def init_shared_dict(socket):
    # TODO: Send read_db message and initialize shared dictionary
    global SHARED_DICTINARY
    SHARED_DICTINARY['read'] = [3]

def main():
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)

    set_program_path(relative_path=argv[1])
    socket = setup_zmq() 
    init_shared_dict(socket=socket)
    
    child = Process(target=child_prozess, args=(SHARED_DICTINARY,argv))
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
                decision = ask_for_permission_zmq(syscall=syscall, socket=socket)
                
                if decision == "ALLOW":
                    #TODO: Safe the decision in the SHARED_DICTINARY and continue
                    print(f"Decision: ALLOW for syscall: {syscall.format()}")

                if decision == "DENY":
                    # TODO: Find another solution than SIGKILL for this problem
                    print(f"Decision: DENY for syscall: {syscall.format()}")
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
