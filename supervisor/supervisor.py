from ptrace.debugger import (PtraceDebugger,ProcessExit,NewProcessEvent)
from ptrace.debugger.child import createChild
from ptrace.func_call import FunctionCallOptions
from sys import stderr, argv, exit

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
        
    pid = createChild(arguments=argv[1:], no_stdout=False, env=None)
    debugger = PtraceDebugger()
    process = debugger.addProcess(pid=pid, is_attached=True)

    # TODO: Do Seccomp filtering according to cache
         
    process.syscall()
        
    while True:
        try: 
            event = debugger.waitSyscall()
            state = event.process.syscall_state
            syscall = state.event(FunctionCallOptions())
    
            if syscall.result is None:
                permission = ask_for_permission(syscall_formated=syscall.format())

                # TODO: Do Seccomp filtering according to decision
                
                # TODO: Add decision to the cache  
                
            process.syscall()
        except NewProcessEvent as event:
            print("Prozess hat ein Kind-Prozess gestartet")
            continue
        except ProcessExit as event:
            print("Prozess beendet")
            break
    
    debugger.quit()
    
if __name__ == "__main__":
    main()