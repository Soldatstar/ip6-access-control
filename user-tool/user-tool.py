import json
import os
import socket
import datetime
from logging_config import configure_logging
from typing import Optional

SOCKET_PATH = "/tmp/mock_user_tool.sock"

BASE_DIR = os.path.join(os.path.dirname(__file__), "process-supervisor")
POLICIES_DIR = os.path.join(BASE_DIR, "policies")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def ensure_directories_exist():
    os.makedirs(POLICIES_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

ensure_directories_exist()

# Configure logging
log_file_path = os.path.join(LOGS_DIR, "user_tool.log")
logger = configure_logging(log_file_path, "User-Tool")

def parse_request(data: str) -> Optional[tuple]:
    try:
        parts = data.split()
        syscall_nr = int(parts[0].split(":")[1])
        program_hash = parts[1].split(":")[1]
        program_name = parts[2].split(":")[1]
        program_path = parts[3].split(":")[1]
        return syscall_nr, program_hash, program_name, program_path
    except (IndexError, ValueError):
        logger.error("Invalid request format")
        return None

def handle_connection(client_sock: socket.socket):
    while True:
        try:
            data = client_sock.recv(256).decode()
            if not data:
                break

            request = parse_request(data)
            if not request:
                client_sock.sendall(b"DENY")
                continue

            syscall_nr, program_hash, program_name, program_path = request

            match input(f"[User-Tool] Allow operation for syscall {syscall_nr} (program: {program_name}, hash: {program_hash})? (y/n/1): ").strip().lower():
                case "1":
                    client_sock.sendall(b"ALLOW")
                    continue
                case "y":
                    response = "ALLOW"
                case "n":
                    response = "DENY"
                case _:
                    response = "DENY"
            client_sock.sendall(response.encode())

            save_decision(program_name, program_path, program_hash, syscall_nr, response)

        except Exception as e:
            logger.error(f"Error handling connection: {e}")
            break

def save_decision(program_name: str, program_path: str, program_hash: str, syscall_nr: int, decision: str, user: str = "user123"):
    process_dir = os.path.join(POLICIES_DIR, program_hash)
    os.makedirs(process_dir, exist_ok=True)
    policy_file = os.path.join(process_dir, "policy.json")

    # Handle empty or invalid policy files
    if os.path.exists(policy_file):
        try:
            with open(policy_file, "r") as file:
                data = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            logger.warning(f"Policy file {policy_file} is empty or invalid. Reinitializing.")
            data = None
    else:
        data = None

    # Initialize policy file if it doesn't exist or is invalid
    if data is None:
        data = {
            "metadata": {
                "process_name": program_name,
                "process_path": program_path,
                "last_modified": None,
                "approved_by": user
            },
            "rules": {
                "allowed_syscalls": [],
                "denied_syscalls": []
            }
        }

    # Update the policy based on the decision
    if decision == "ALLOW":
        if syscall_nr not in data["rules"]["allowed_syscalls"]:
            data["rules"]["allowed_syscalls"].append(syscall_nr)
    else:
        if syscall_nr not in data["rules"]["denied_syscalls"]:
            data["rules"]["denied_syscalls"].append(syscall_nr)

    data["metadata"]["last_modified"] = datetime.datetime.now().isoformat()

    # Save the updated policy
    with open(policy_file, "w") as file:
        json.dump(data, file, indent=4)

def main():
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server_sock:
        server_sock.bind(SOCKET_PATH)
        server_sock.listen(5)
        logger.info(f"Mock user-tool started. Listening on {SOCKET_PATH}")

        while True:
            logger.info("Waiting for connection...")
            client_sock, _ = server_sock.accept()
            logger.info("Supervisor connected. Ready to handle requests.")
            with client_sock:
                handle_connection(client_sock)

if __name__ == "__main__":
    main()
