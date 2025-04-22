from sys import stderr, argv, exit
from os import execv
from multiprocessing import Manager, Process

import zmq
import json

from ptrace.debugger import (PtraceDebugger,ProcessExit,NewProcessEvent,ProcessSignal)
from ptrace.func_call import FunctionCallOptions
from pyseccomp import SyscallFilter, ALLOW, TRAP, Arg, EQ


def init_seccomp(syscall_to_filter):
    f = SyscallFilter(defaction=ALLOW)
    
    for key in list(syscall_to_filter.keys()):
        for i in range(len(syscall_to_filter[key])):
            f.add_rule(TRAP, key, Arg(i, EQ, syscall_to_filter[key][i]))

    f.load()

def child_prozess(shared_dict,argv):
    init_seccomp(syscall_to_filter=shared_dict)
    execv(argv[1],[argv[1]]+argv[2:])

def ask_for_permission(syscall_formated):
    # TODO: Change here for communication whit user-tool using ZeroMQ -> see ask_for_permission_zmq
    while True:
        permission = input(f"Systemcall '{syscall_formated}' (ALLOW,DENY): ")
        if permission == 'ALLOW' or permission == 'DENY':
            return permission
        else:
            print("Illegal input. Please choose ALLOW or DENY")

def setup_zmq() -> zmq.Socket:
    context = zmq.Context()
    socket = context.socket(zmq.DEALER)
    socket.connect("tcp://localhost:5556")
    return socket

def ask_for_permission_zmq(syscall_formated, socket):

    # TODO: extract program name, syscall_id and parameter from the message
    message = {
        "type": "req_decision",
        "body": {
            "program": "/home/user/file-access",
            "syscall_id": syscall_formated,
            "parameter": "some_parameter"
        }
    }
    print(f" \n [Supervisor] Sending: {json.dumps(message)}")
    socket.send_multipart([b'', json.dumps(message).encode()])  
    try:
        while True:
                _, response = socket.recv_multipart()
                response_data = json.loads(response.decode())
                print("Received response from user-tool:", response_data)
                break
    except KeyboardInterrupt:
        print("Exiting supervisor...")
    finally:
        socket.close()


def main():
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)

    # TODO: Connection to user-tool over ZeroMQ
    socket = setup_zmq()

    # TODO: Wait for read_db, store it into the cache, put the path of the program into the message 
    manager = Manager()  
    shared_dict = manager.dict()
    shared_dict['read'] = [3]
    
    child = Process(target=child_prozess, args=(shared_dict,argv))
    child.start()
    debugger = PtraceDebugger()
    process = debugger.addProcess(pid=child.pid, is_attached=False)
      
    process.syscall()
    
    while True:
        try: 
            event = debugger.waitSyscall()
            state = event.process.syscall_state
            syscall = state.event(FunctionCallOptions())
    
            if syscall.result is None:
                # TODO: Ask for permission and change the seccomp filter
                # permission = ask_for_permission(syscall_formated=syscall.format())
                print(syscall.format())  
                ask_for_permission_zmq(syscall.format(), socket)
            
            process.syscall()
        
        except ProcessSignal as event: 
            print(f"***SIGNAL {event.getSignalInfo}***")
            break

        except NewProcessEvent as event:
            print("***CHILD-PROCESS***")
            continue

        except ProcessExit as event:
            print("***PROCESS-EXECUTED***")
            break
    
    debugger.quit()
    child.join()
    manager.shutdown() 
    socket.close()
    
    
if __name__ == "__main__":
    main()
