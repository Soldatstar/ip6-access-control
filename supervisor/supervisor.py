from sys import stderr, argv, exit
from os import execv
from multiprocessing import Array, Event, Process

from ptrace.debugger import (PtraceDebugger,ProcessExit,NewProcessEvent,ProcessSignal)
from ptrace.func_call import FunctionCallOptions
from pyseccomp import SyscallFilter, ALLOW, TRAP

def init_seccomp():
    f = SyscallFilter(defaction=ALLOW)
    #f.add_rule(TRAP, 'close')
    f.load()

def child_prozess(event,shared_memory,argv):
    init_seccomp()
    event.wait()
    execv(argv[1],[argv[1]]+argv[2:])

def ask_for_permission(syscall_formated):
    # TODO: Change here for communication whit user-tool using ZeroMQ
    while True:
        permission = input(f"Systemcall '{syscall_formated}' (ALLOW,DENY): ")
        if permission == 'ALLOW' or permission == 'DENY':
            return permission
        else:
            print("Illegal input. Please choose ALLOW or DENY")

def main():
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)

    # TODO: Connection to user-tool over ZeroMQ

    # TODO: Wait for read_db, store it into the cache, put the path of the program into the message 
    shared_memory = Array("i",1)
    shared_memory[0] = 2
    
    event = Event()
    child = Process(target=child_prozess, args=(event, shared_memory,argv))
    child.start()
    debugger = PtraceDebugger()
    process = debugger.addProcess(pid=child.pid, is_attached=False)
    event.set()
      
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
    
if __name__ == "__main__":
    main()
