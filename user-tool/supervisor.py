import json
import os
import socket
from logging_config import configure_logging
from typing import Optional

from ptrace.debugger import (PtraceDebugger,ProcessExit,NewProcessEvent)
from ptrace.debugger.child import createChild
from ptrace.func_call import FunctionCallOptions
from sys import stderr, argv, exit

SOCKET_PATH = "/tmp/mock_user_tool.sock"

BASE_DIR = os.path.join(os.path.dirname(__file__), "process-supervisor")
POLICIES_DIR = os.path.join(BASE_DIR, "policies")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Configure logging
log_file_path = os.path.join(LOGS_DIR, "supervisor.log")
logger = configure_logging(log_file_path, "Supervisor")

def check_decision_json(program_hash: str, syscall_nr: int) -> Optional[str]:
    process_dir = os.path.join(POLICIES_DIR, program_hash)
    policy_file = os.path.join(process_dir, "policy.json")

    if not os.path.exists(policy_file):
        return None

    try:
        with open(policy_file, "r") as file:
            data = json.load(file)
    except json.JSONDecodeError:
        logger.error(f"Policy file {policy_file} is empty or invalid.")
        return None

    for syscall, parameter in data.get("rules", {}).get("denied_syscalls", []):
        if syscall == syscall_nr:
            return "DENY"
    for syscall, parameter in data.get("rules", {}).get("allowed_syscalls", []):
        if syscall == syscall_nr:
            return "ALLOW"
    return None

def ask_user_tool(client_sock: socket.socket, syscall_nr: int, program_hash: str, program_name: str, program_path: str) -> str:
    request = f"SYSCALL:{syscall_nr} NAME:{program_name} HASH:{program_hash} PATH:{program_path}"  
    logger.info(f"Requesting decision from user-tool: {request}")
    client_sock.sendall(request.encode())
    response = client_sock.recv(256).decode().strip()
    logger.info(f"User-tool response: {response}")
    return response

def get_decision_from_policy(program_hash: str, syscall_nr: int) -> Optional[str]:
    """Check the policy file for a decision."""
    decision = check_decision_json(program_hash, syscall_nr)
    if decision:
        logger.info(f"Decision found in policy file: {decision}")
    return decision

def get_decision_from_user_tool(client_sock: socket.socket, syscall_nr: int, program_hash: str, program_name: str, program_path: str) -> str:
    """Ask the user tool for a decision."""
    decision = ask_user_tool(client_sock, syscall_nr, program_hash, program_name, program_path)
    logger.info(f"Decision from user-tool: {decision}")
    return decision

def simulate_syscall(client_sock: socket.socket, syscall_nr: int, program_name: str, program_hash: str, program_path: str):
    """
    Simulate a syscall and determine its decision based on the policy file or user tool.
    """
    logger.info(f"Simulating syscall {syscall_nr} for program {program_name} with hash {program_hash}")

    # Check decision from policy file
    decision = get_decision_from_policy(program_hash, syscall_nr)
    if decision:
        logger.info(f"Decision from policy file: {decision}")
        return decision  # Return the decision if found in the policy file

    # Ask user tool for permission if no decision is found in the policy file
    decision = get_decision_from_user_tool(client_sock, syscall_nr, program_name, program_hash, program_path)
    logger.info(f"Decision from user-tool: {decision}")
    return decision


def main():
    # Überprüfe ob genau ein Programm übergeben wurde welches beobachtet werden soll
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)

    # TODO: hash and path needs to be calucated
    program_name = argv[1:]
    program_hash = "1234567890abcdef"
    program_path = "/usr/bin/mockApp"

    # Connect to user tool
    logger.info("Connecting to user-tool...")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_sock:
        try:
            client_sock.connect(SOCKET_PATH)
            logger.info("Connected to user-tool")
        except Exception as e:
            logger.error(f"Failed to connect to user-tool: {e}")
            logger.error("Make sure the user-tool is running!")
            return
        
        # Erstelle den Process, welcher beobachtet werden soll
        pid = createChild(arguments=argv[1:], no_stdout=False, env=None)
    
        # Erstelle den Debugger und füge den Process dem Debugger hinzu
        debugger = PtraceDebugger()
        process = debugger.addProcess(pid=pid, is_attached=True)
        
        # Setze den ersten Systemaufruf Breakpoint 
        process.syscall()
        
        # Der Debugger fängt Systemaufrufe auf, diese werden auf die Console geprinted und der nächste Systemaufruf Breakpoint wird gesetzt
        while True:
            try: 
                event = debugger.waitSyscall()
                state = event.process.syscall_state
                syscall = state.event(FunctionCallOptions())
    
                # Nur wenn der Systemaufruf noch nicht ausgeführt wurde soll er angezeigt
                # TODO: parameter for arguments = [arg.format() for arg in syscall.arguments] and syscall.name
                if syscall.result is None:
                    decision = simulate_syscall(client_sock, syscall.syscall, program_name, program_hash, program_path)
                    logger.info(f"Final decision for syscall {syscall.syscall}: {decision}")

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