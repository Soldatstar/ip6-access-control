#!/usr/bin/env python3
from ptrace.debugger import (PtraceDebugger,ProcessExit,NewProcessEvent)
from ptrace.debugger.child import createChild
from ptrace.func_call import FunctionCallOptions
from sys import stderr, argv, exit

def extractSyscall(event,type=None):
    state = event.process.syscall_state
    syscall = state.event(FunctionCallOptions())
    
    # Nur wenn der Systemaufruf noch nicht ausgeführt wurde soll er angezeigt
    if syscall.result is None:
        match type:
            case "name":
                print(syscall.name)
            case "number":
                print(syscall.syscall)    
            case "arguments":
                arguments = [arg.format() for arg in syscall.arguments]
                print("Args %s : %s" % (syscall.name, arguments))
            case _: 
                print(syscall.format())

def printSyscalls(process,debugger):
    # Setze den ersten Systemaufruf Breakpoint 
    process.syscall()
    
    # Der Debugger fängt Systemaufrufe auf, diese werden auf die Console geprinted und der nächste Systemaufruf Breakpoint wird gesetzt
    while True:
        try: 
            event = debugger.waitSyscall()
            extractSyscall(event=event)
            process.syscall()
        except NewProcessEvent as event:
            print("Prozess hat ein Kind-Prozess gestartet")
            continue
        except ProcessExit as event:
            print("Prozess beendet")
            break

def main():
    # Überprüfe ob genau ein Programm übergeben wurde welches beobachtet werden soll
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)

    # Erstelle den Process, welcher beobachtet werden soll
    pid = createChild(arguments=argv[1:], no_stdout=False, env=None)
    
    # Erstelle den Debugger und füge den Process dem Debugger hinzu
    debugger = PtraceDebugger()
    process = debugger.addProcess(pid=pid, is_attached=True)

    # Gib alle Systemaufrufe auf der Konsole aus
    printSyscalls(process=process,debugger=debugger)
    debugger.quit()

if __name__ == "__main__":
    main()