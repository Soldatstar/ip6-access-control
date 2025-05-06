"""
Main module for the User Tool.

This module provides the main entry point for the user tool, which allows users to:
- Interact with syscall policies via a menu-driven interface.
- Handle incoming requests for syscall decisions using ZeroMQ.
- Manage policies, including listing and deleting them.
"""

import json
import os
import threading
import queue

import hashlib
import sys
from pathlib import Path
import zmq

# Add the parent directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from user_tool import policy_manager
from user_tool import user_interaction
from shared import logging_config
from user_tool.policy_manager import Policy

# Directories
BASE_DIR = Path(__file__).resolve().parent.parent / "process-supervisor"
POLICIES_DIR = BASE_DIR / "policies"
LOGS_DIR = BASE_DIR / "logs"

# Ensure required directories exist
POLICIES_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
log_file_path = LOGS_DIR / "user_tool.log"
LOGGER = logging_config.configure_logging(log_file_path, "User-Tool")

# Global variables
REQUEST_QUEUE = queue.Queue()
NEW_REQUEST_EVENT = threading.Event()

# Delegate variables to policy_manager
policy_manager.POLICIES_DIR = str(POLICIES_DIR)
policy_manager.LOGGER = LOGGER


def zmq_listener():
    """
    Background thread to listen for incoming ZeroMQ requests.

    This function sets up a ZeroMQ listener on a specified port and processes
    incoming requests. It adds valid requests to a queue for further handling.
    """
    context = zmq.Context()
    socket = context.socket(zmq.ROUTER)
    socket.bind("tcp://*:5556")
    LOGGER.info("ZeroMQ listener started on tcp://%s", "*:5556")

    while True:
        try:
            # Receive message: [identity, delimiter, message]
            identity, *_, message = socket.recv_multipart()
            LOGGER.debug("Received request from %s: %s", identity, message)
            try:
                message = json.loads(message.decode())
                REQUEST_QUEUE.put((socket, identity, message))
                NEW_REQUEST_EVENT.set()
            except json.JSONDecodeError:
                LOGGER.error("Failed to decode JSON message")
                socket.send_multipart(
                    [identity, b'', json.dumps({"error": "Invalid JSON"}).encode()])
        except zmq.ZMQError as e:
            LOGGER.error("ZeroMQ error: %s", e)
            break


def handle_requests():
    """
    Handle requests from the queue.

    This function processes requests from the queue, determines the type of
    request (e.g., syscall decision or policy read), and performs the appropriate
    actions. It sends responses back to the requester.
    """
    while not REQUEST_QUEUE.empty():
        socket, identity, message = REQUEST_QUEUE.get()

        # Extract fields from the new message format
        if message.get("type") == "req_decision" and "body" in message:
            LOGGER.info("Received req_decision request")
            body = message["body"]
            program_path = body.get("program")
            syscall_nr = body.get("syscall_id")
            syscall_name = body.get("syscall_name")
            parameter = body.get("parameter_raw", "no_parameter")
            parameter_formated = body.get("parameter_formated", "no_parameter")

            # Calculate the hash of the program path
            program_hash = hashlib.sha256(program_path.encode()).hexdigest()

            # Extract the program name from the path
            program_name = os.path.basename(program_path)

        elif message.get("type") == "read_db" and "body" in message:
            LOGGER.info("Received read_db request")
            body = message["body"]
            program_path = body.get("program")
            program_hash = hashlib.sha256(program_path.encode()).hexdigest()
            # read policy file if it exists
            policy_file = os.path.join(
                POLICIES_DIR, program_hash, "policy.json")

            response = None
            if os.path.exists(policy_file) and os.path.getsize(policy_file) > 0:
                with open(policy_file, "r", encoding="UTF-8") as file:
                    try:
                        data = json.load(file)
                        LOGGER.debug("Policy for %s: %s",
                                     program_hash, json.dumps(data, indent=4))
                        rules = data.get("rules", {})
                        response = {
                            "status": "success",
                            "data": rules
                        }
                    except json.JSONDecodeError:
                        LOGGER.error(
                            "Policy file for %s is invalid.", program_hash)
                        response = {
                            "status": "error",
                            "data": {"message": "Invalid policy file"}
                        }
            else:
                LOGGER.info("No policy found for %s", program_hash)
                response = {
                    "status": "error",
                    "data": {"message": "No policy found"}
                }
            socket.send_multipart(
                [identity, b'', json.dumps(response).encode()])
            continue
        else:
            # Handle invalid message format
            LOGGER.error("Invalid message format")
            error_response = {
                "status": "error",
                "data": {"message": "Invalid message format"}
            }
            socket.send_multipart(
                [identity, b'', json.dumps(error_response).encode()])
            continue
        LOGGER.info("Handling request for %s (hash: %s)",
                    program_name, program_hash)
        LOGGER.info("Syscall: %s (ID: %s parameter: %s)",
                    syscall_name, syscall_nr, parameter)
        response = user_interaction.ask_permission(
            syscall_nr, program_name, program_hash, parameter_formated, LOGGER)

        match response:
            case "ONE_TIME":  # Allow for one time without saving
                LOGGER.info(
                    "User allowed the request for one time for %s (hash: %s)",
                     program_name, program_hash)
                response = "ALLOW"
            case "ALLOW":
                LOGGER.info("User allowed the request for %s (hash: %s)",
                            program_name, program_hash)
                policy = Policy(
                    program_path, program_hash, syscall_nr, "ALLOW", "placeholder_user", parameter
                )
                policy_manager.save_decision(policy)
            case "DENY":
                LOGGER.info("User denied the request for %s (hash: %s)",
                            program_name, program_hash)
                policy = Policy(
                    program_path, program_hash, syscall_nr, "DENY", "placeholder_user", parameter
                )
                policy_manager.save_decision(policy)
            case _:
                LOGGER.error("Unknown response: %s", response)
                response = "DENY"

        # Send the response back to the requester in the specified format
        success_response = {
            "status": "success",
            "data": {"decision": response}
        }
        socket.send_multipart(
            [identity, b'', json.dumps(success_response).encode()])

    NEW_REQUEST_EVENT.clear()  # Clear the event after handling all requests


def main(test_mode=False):
    """
    Main entry point for the User Tool.

    This function starts the ZeroMQ listener in a background thread and provides
    a menu-driven interface for the user to interact with syscall policies.

    Args:
        test_mode (bool): If True, the function will exit after one iteration of the loop.
    """
    # Start the ZeroMQ listener in a background thread
    listener_thread = threading.Thread(target=zmq_listener, daemon=True)
    listener_thread.start()

    while True:
        LOGGER.info("User Tool Menu:")
        LOGGER.info("1. List Known Apps")
        LOGGER.info("2. Delete All Policies")
        LOGGER.info("3. Exit")

        LOGGER.info("Waiting for user input...")
        while not NEW_REQUEST_EVENT.is_set():
            choice = user_interaction.non_blocking_input("")
            if choice:
                break

        if NEW_REQUEST_EVENT.is_set():
            LOGGER.info("\n[Notification] New request received! Handling it now...")
            handle_requests()
            continue

        elif choice == "1":
            os.system('clear')
            LOGGER.info("Listing known apps...")
            policy_manager.list_known_apps()
            input("Press Enter to return to the menu...")
        elif choice == "2":
            os.system('clear')
            LOGGER.info("Deleting all policies...")
            policy_manager.delete_all_policies()
            input("Press Enter to return to the menu...")
        elif choice == "3":
            os.system('clear')
            LOGGER.info("Exiting User Tool.")
            break
        else:
            LOGGER.warning("Invalid choice. Please try again.")

        if test_mode:
            break  # Exit the loop after one iteration in test mode


if __name__ == "__main__":
    main()
