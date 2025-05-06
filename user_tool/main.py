import json
import os
import zmq
import threading
import queue
import sys
import select
import tkinter as tk
import hashlib
from pathlib import Path

# Add the project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from shared.logging_config import configure_logging
from user_tool import utils

# Directories
BASE_DIR = Path(__file__).resolve().parent.parent / "process-supervisor"
POLICIES_DIR = BASE_DIR / "policies"
LOGS_DIR = BASE_DIR / "logs"

# Ensure required directories exist
POLICIES_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
log_file_path = LOGS_DIR / "user_tool.log"
logger = configure_logging(log_file_path, "User-Tool")

# Global variables
REQUEST_QUEUE = queue.Queue()
NEW_REQUEST_EVENT = threading.Event()

# Delegate variables to policy_manager
from user_tool import policy_manager
policy_manager.POLICIES_DIR = str(POLICIES_DIR)
policy_manager.logger = logger

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
            parameter = body.get("parameter_raw", "no_parameter")
            parameter_formated = body.get("parameter_formated", "no_parameter")

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
        logger.info(f"Syscall: {syscall_name} (ID: {syscall_nr} parameter: {parameter})")
        response = utils.ask_permission(syscall_nr, program_name, program_hash, parameter_formated, logger)

        match response:
            case "ONE_TIME":  # Allow for one time without saving
                logger.info(f"User allowed the request for one time for {program_name} (hash: {program_hash})")
                response = "ALLOW"
            case "ALLOW":
                logger.info(f"User allowed the request for {program_name} (hash: {program_hash})")
                policy_manager.save_decision(program_name, program_path, program_hash, syscall_nr, response, "placeholder_user", parameter)
            case "DENY":
                logger.info(f"User denied the request for {program_name} (hash: {program_hash})")
                policy_manager.save_decision(program_name, program_path, program_hash, syscall_nr, response, "placeholder_user", parameter)
            case _:
                logger.error(f"Unknown response: {response}")
                response = "DENY"

        # Send the response back to the requester in the specified format
        success_response = {
            "status": "success",
            "data": {"decision": response}
        }
        socket.send_multipart([identity, b'', json.dumps(success_response).encode()])

    NEW_REQUEST_EVENT.clear()  # Clear the event after handling all requests

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
            choice = utils.non_blocking_input("")
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
