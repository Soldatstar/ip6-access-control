import json
import os
import socket
import datetime
import shutil  
import zmq
import threading
import queue
import sys
import select
import tkinter as tk
from logging_config import configure_logging
import hashlib  

BASE_DIR = os.path.join(os.path.dirname(__file__), "process-supervisor")
POLICIES_DIR = os.path.join(BASE_DIR, "policies")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

REQUEST_QUEUE = queue.Queue()           # Queue to hold incoming requests
NEW_REQUEST_EVENT = threading.Event()   # Event to signal new requests

def ensure_directories_exist():
    os.makedirs(POLICIES_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

ensure_directories_exist()

# Configure logging
log_file_path = os.path.join(LOGS_DIR, "user_tool.log")
logger = configure_logging(log_file_path, "User-Tool")

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
        logger.info("No policies directory found.")
        return

    apps = os.listdir(POLICIES_DIR)
    if not apps:
        logger.info("No known applications with policies.")
    else:
        logger.info("Known applications with policies:")
        for app in apps:
            policy_file = os.path.join(POLICIES_DIR, app, "policy.json")
            if os.path.exists(policy_file):
                try:
                    with open(policy_file, "r") as file:
                        data = json.load(file)
                        process_name = data.get("metadata", {}).get("process_name", "Unknown")
                        logger.info(f"- {process_name} (Hash: {app})")
                except json.JSONDecodeError:
                    logger.warning(f"- {app} (Invalid policy file)")
            else:
                logger.warning(f"- {app} (No policy file found)")

def delete_all_policies():
    """Delete all policies."""
    if not os.path.exists(POLICIES_DIR):
        logger.info("No policies directory found.")
        return

    for app in os.listdir(POLICIES_DIR):
        app_path = os.path.join(POLICIES_DIR, app)
        if os.path.isdir(app_path):
            try:
                shutil.rmtree(app_path) 
                logger.info(f"Deleted policies for {app}.")
            except Exception as e:
                logger.error(f"Failed to delete policies for {app}. Error: {e}")

    logger.info("All policies deleted.")

def zmq_listener():
    """Background thread to listen for incoming ZeroMQ requests."""
    context = zmq.Context()
    socket = context.socket(zmq.ROUTER)  
    socket.bind("tcp://*:5556")  
    logger.info("ZeroMQ listener started on tcp://*:5556")

    while True:
        try:
            # Receive message: [identity, delimiter, message]
            identity, _, message = socket.recv_multipart()
            logger.debug(f"Received request from {identity}: {message}")
            try:
                message = json.loads(message.decode())
                REQUEST_QUEUE.put((socket, identity, message))  # Add the request to the queue
                NEW_REQUEST_EVENT.set()                         # Signal that a new request has arrived
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON message")
                socket.send_multipart([identity, b'', json.dumps({"error": "Invalid JSON"}).encode()])
        except zmq.ZMQError as e:
            logger.error(f"ZeroMQ error: {e}")
            break

def handle_requests():
    """Handle requests from the queue."""
    while not REQUEST_QUEUE.empty():
        socket, identity, message = REQUEST_QUEUE.get()
        
        # Extract fields from the new message format
        if message.get("type") == "req_decision" and "body" in message:
            logger.info("Received req_decision request")
            body = message["body"]
            program_path = body.get("program")
            syscall_nr = body.get("syscall_id")
            syscall_name= body.get("syscall_name")
            parameter = body.get("parameter", "no_parameter")

            # Calculate the hash of the program path
            program_hash = hashlib.sha256(program_path.encode()).hexdigest()

            # Extract the program name from the path
            program_name = os.path.basename(program_path)

        elif message.get("type") == "read_db" and "body" in message:
            logger.info("Received read_db request")
            body = message["body"]
            program_path = body.get("program")
            program_hash = hashlib.sha256(program_path.encode()).hexdigest()
            #read policy file if it exists
            policy_file = os.path.join(POLICIES_DIR, program_hash, "policy.json")

            response = None
            if os.path.exists(policy_file) and os.path.getsize(policy_file) > 0:
                with open(policy_file, "r") as file:
                    try:
                        data = json.load(file)
                        logger.debug(f"Policy for {program_hash}: {json.dumps(data, indent=4)}")
                        rules = data.get("rules", {})
                        response = {
                            "status": "success",
                            "data": rules
                        }
                    except json.JSONDecodeError:
                        logger.error(f"Policy file for {program_hash} is invalid.")
                        response = {
                            "status": "error",
                            "data": {"message": "Invalid policy file"}
                        }
            else:
                logger.info(f"No policy found for {program_hash}")
                response = {
                    "status": "error",
                    "data": {"message": "No policy found"}
                }
            socket.send_multipart([identity, b'', json.dumps(response).encode()])
            continue
        else:
            # Handle invalid message format
            logger.error("Invalid message format")
            error_response = {
                "status": "error",
                "data": {"message": "Invalid message format"}
            }
            socket.send_multipart([identity, b'', json.dumps(error_response).encode()])
            continue
        logger.info(f"Handling request for {program_name} (hash: {program_hash})")
        response = ask_permission(syscall_nr, program_name, program_hash)

        match response:
            case "ONE_TIME":  # Allow for one time without saving
                response = "ALLOW"
            case "ALLOW":
                save_decision(program_name, program_path, program_hash, syscall_nr, response, "placeholder_user", parameter)
            case "DENY":
                save_decision(program_name, program_path, program_hash, syscall_nr, response, "placeholder_user", parameter)
            case _:
                response = "DENY"

        # Send the response back to the requester in the specified format
        success_response = {
            "status": "success",
            "data": {"decision": response}
        }
        socket.send_multipart([identity, b'', json.dumps(success_response).encode()])

    NEW_REQUEST_EVENT.clear()  # Clear the event after handling all requests

def ask_permission(syscall_nr, program_name, program_hash):
    decision = {'value': None}
    q = queue.Queue()
    after_id = None

    def set_decision(choice):
        nonlocal after_id
        if decision['value'] is None:
            decision['value'] = choice
            # cancel any pending poll_queue callback
            if after_id is not None:
                try:
                    root.after_cancel(after_id)
                except tk.TclError:
                    pass
            root.destroy()

    def ask_cli():
        prompt = (
            f"Allow operation for syscall {syscall_nr}?\n"
            f"Program: {program_name}\n"
            f"Hash: {program_hash}\n"
            "( (y)es / (n)o / (o)ne ): "
        )
        mapping = {
            'yes': 'ALLOW',   'y': 'ALLOW',
            'no':  'DENY',    'n': 'DENY',
            'one': 'ONE_TIME','o': 'ONE_TIME',
        }

        logger.info(prompt)

        # poll stdin until GUI decision or valid CLI answer
        while decision['value'] is None:
            r, _, _ = select.select([sys.stdin], [], [], 4.0)
            if r:
                ans = sys.stdin.readline().strip().lower()
                choice = mapping.get(ans)
                if choice:
                    q.put(choice)
                    break

    def poll_queue():
        nonlocal after_id
        try:
            choice = q.get_nowait()
        except queue.Empty:
            # schedule next poll
            after_id = root.after(100, poll_queue)
        else:
            set_decision(choice)

    root = tk.Tk()
    root.title("Permission Request")
    root.geometry("400x150")

    lbl = tk.Label(
        root,
        text=(
            f"Allow operation for syscall {syscall_nr}?\n"
            f"Program: {program_name}\n"
            f"Hash: {program_hash}"
        ),
        wraplength=350
    )
    lbl.pack(pady=20)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)
    for txt, val in [("Allow","ALLOW"), ("Deny","DENY"), ("One Time","ONE_TIME")]:
        tk.Button(btn_frame, text=txt, width=10,
                  command=lambda v=val: set_decision(v)).pack(side=tk.LEFT, padx=5)

    threading.Thread(target=ask_cli, daemon=True).start()
    after_id = root.after(100, poll_queue)

    root.mainloop()

def non_blocking_input(prompt: str, timeout: float = 0.5) -> str:
    """Simulate non-blocking input with a timeout."""
    print(prompt, end='', flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    return None

def main():
    # Start the ZeroMQ listener in a background thread
    listener_thread = threading.Thread(target=zmq_listener, daemon=True)
    listener_thread.start()

    while True:
        #os.system('clear')  # Clear the console
        logger.info("User Tool Menu:")
        logger.info("1. List Known Apps")
        logger.info("2. Delete All Policies")
        logger.info("3. Exit")

        logger.info("Waiting for user input...")
        while not NEW_REQUEST_EVENT.is_set():
            choice = non_blocking_input("")
            if choice:
                break

        if NEW_REQUEST_EVENT.is_set():
            logger.info("\n[Notification] New request received! Handling it now...")
            handle_requests()
            continue

        elif choice == "1":
            os.system('clear')
            logger.info("Listing known apps...")
            list_known_apps()
            input("Press Enter to return to the menu...")
        elif choice == "2":
            os.system('clear')
            logger.info("Deleting all policies...")
            delete_all_policies()
            input("Press Enter to return to the menu...")
        elif choice == "3":
            os.system('clear')
            logger.info("Exiting User Tool.")
            break
        else:
            logger.warning("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
