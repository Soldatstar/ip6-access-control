import json
import os
import socket
import datetime
import shutil  # Add this import at the top of the file
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
        logger.info(f"Parsed request: syscall_nr={syscall_nr}, program_name={program_name}, program_hash={program_hash}, program_path={program_path}")
        return syscall_nr, program_name, program_hash, program_path
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

            syscall_nr, program_name, program_hash, program_path = request

            match input(f"[User-Tool] Allow operation for syscall {syscall_nr} (program: {program_name}, hash: {program_hash})? (y/n/1): ").strip().lower():
                case "1": # Allow for one time without saving
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

def save_decision(program_name: str, program_path: str, program_hash: str, syscall_nr: int, decision: str, user: str = "user123", parameter: str = "parameter"):
    process_dir = os.path.join(POLICIES_DIR, program_hash)  
    os.makedirs(process_dir, exist_ok=True)
    logger.info(f"Saving decision for {program_name} (hash: {program_hash}) in {process_dir}")
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
    syscall_entry = [syscall_nr, parameter]
    if decision == "ALLOW":
        if syscall_entry not in data["rules"]["allowed_syscalls"]:
            data["rules"]["allowed_syscalls"].append(syscall_entry)
    else:
        if syscall_entry not in data["rules"]["denied_syscalls"]:
            data["rules"]["denied_syscalls"].append(syscall_entry)

    data["metadata"]["last_modified"] = datetime.datetime.now().isoformat()

    # Save the updated policy
    with open(policy_file, "w") as file:
        json.dump(data, file, indent=4)

def list_known_apps():
    """List all applications with known policies."""
    if not os.path.exists(POLICIES_DIR):
        print("No policies directory found.")
        return

    apps = os.listdir(POLICIES_DIR)
    if not apps:
        print("No known applications with policies.")
    else:
        print("Known applications with policies:")
        for app in apps:
            policy_file = os.path.join(POLICIES_DIR, app, "policy.json")
            if os.path.exists(policy_file):
                try:
                    with open(policy_file, "r") as file:
                        data = json.load(file)
                        process_name = data.get("metadata", {}).get("process_name", "Unknown")
                        print(f"- {process_name} (Hash: {app})")
                except json.JSONDecodeError:
                    print(f"- {app} (Invalid policy file)")
            else:
                print(f"- {app} (No policy file found)")

def delete_all_policies():
    """Delete all policies."""
    if not os.path.exists(POLICIES_DIR):
        print("No policies directory found.")
        return

    for app in os.listdir(POLICIES_DIR):
        app_path = os.path.join(POLICIES_DIR, app)
        if os.path.isdir(app_path):
            try:
                shutil.rmtree(app_path) 
                print(f"Deleted policies for {app}.")
            except Exception as e:
                print(f"Failed to delete policies for {app}. Error: {e}")

    print("All policies deleted.")

def main():
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    while True:
        os.system('clear')  # Clear the console
        print("\nUser Tool Menu:")
        print("1. Accept supervisor connection")
        print("2. List Known Apps")
        print("3. Delete All Policies")
        print("4. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            os.system('clear')
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
                    #break
        elif choice == "2":
            os.system('clear')
            list_known_apps()
            input("Press Enter to return to the menu...")
        elif choice == "3":
            os.system('clear')
            delete_all_policies()
            input("Press Enter to return to the menu...")
        elif choice == "4":
            os.system('clear')
            print("Exiting User Tool.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
