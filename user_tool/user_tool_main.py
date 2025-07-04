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
import logging
import argparse

# Add the parent directory to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from user_tool import policy_manager
from user_tool import user_interaction
from user_tool import group_selector
from shared import conf_utils
from user_tool.policy_manager import Policy

# Directories
POLICIES_DIR, LOGS_DIR, LOGGER = conf_utils.setup_directories("user_tool.log", "User-Tool")
LOGGER.propagate = False  # Prevent double logging

# Global variables
REQUEST_QUEUE = queue.Queue()
NEW_REQUEST_EVENT = threading.Event()

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
            # Read all group names from the groups file
            all_groups = set(group_selector.get_groups_structure("user_tool/groups").keys())

            if os.path.exists(policy_file) and os.path.getsize(policy_file) > 0:
                with open(policy_file, "r", encoding="UTF-8") as file:
                    try:
                        data = json.load(file)
                        LOGGER.debug("Policy for %s: %s",
                                     program_hash, json.dumps(data, indent=4))
                        rules = data.get("rules", {})
                        default_policy_path = os.path.join(
                            Path(__file__).resolve().parent, "default.json")
                        with open(default_policy_path, "r", encoding="UTF-8") as default_file:
                            default_data = json.load(default_file)
                            default_syscalls = default_data.get("rules", {}).get("allowed_syscalls", [])
                            rules["allowed_syscalls"] = default_syscalls + rules.get("allowed_syscalls", [])
                        rules["denied_syscalls"] = rules.get("denied_syscalls", [])
                        # Determine blacklist
                        allowed_groups = set(rules.get("allowed_groups", []))
                        if not allowed_groups:
                            # No allowed_groups: blacklist all groups
                            blacklisted_groups = all_groups
                        else:
                            # Blacklist = all groups - allowed_groups
                            blacklisted_groups = all_groups - allowed_groups

                        # Expand to syscall IDs
                        blacklisted_ids = []
                        for group in blacklisted_groups:
                            blacklisted_ids.extend(group_selector.get_syscalls_for_group(group))
                        rules["blacklisted_ids"] = sorted(set(blacklisted_ids))

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
                # Load default policy
                default_policy_path = os.path.join(
                    Path(__file__).resolve().parent, "default.json")
                with open(default_policy_path, "r", encoding="UTF-8") as default_file:
                    default_data = json.load(default_file)
                    rules = default_data.get("rules", {})
                    # Blacklist all groups if no policy
                    blacklisted_groups = all_groups
                    blacklisted_ids = []
                    for group in blacklisted_groups:
                        blacklisted_ids.extend(group_selector.get_syscalls_for_group(group))
                    rules["blacklisted_ids"] = sorted(set(blacklisted_ids))
                    response = {
                        "status": "success",
                        "data": rules
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
        LOGGER.debug("Syscall: %s (ID: %s parameter: %s)",
                    syscall_name, syscall_nr, parameter)
        LOGGER.debug("Syscall: %s (ID: %s parameter: %s)",
                    syscall_name, syscall_nr, parameter_formated)
        response = user_interaction.ask_permission(
            syscall_nr, syscall_name, program_name, program_hash, parameter_formated, parameter)

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
                group = group_selector.get_group_for_syscall(syscall_nr)
                policy_manager.save_decision(policy, allowed_group=group)
                allowed_ids = group_selector.get_syscalls_for_group(group)
                ######
                # TODO: Currently all Syscalls in a group will be removed from the blacklist except FileAccess
                #if group == "FileAccess": 
                #    allowed_ids = []
                ######

                success_response = {
                    "status": "success",
                    "data": {
                        "decision": response,
                        "allowed_ids": allowed_ids
                    }
                }
                socket.send_multipart(
                    [identity, b'', json.dumps(success_response).encode()])
                continue
            case "ALLOW_THIS":
                LOGGER.info("User allowed only this syscall/parameter for %s (hash: %s)",
                            program_name, program_hash)
                policy = Policy(
                    program_path, program_hash, syscall_nr, "ALLOW", "placeholder_user", parameter
                )
                policy_manager.save_decision(policy)
                # Only allow this syscall with this parameter
                success_response = {
                    "status": "success",
                    "data": {
                        "decision": response,
                        "allowed_ids": []
                    }
                }
                socket.send_multipart(
                    [identity, b'', json.dumps(success_response).encode()])
                continue
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


def main(test_mode=False, debug=False):
    """
    Main entry point for the User Tool.

    This function starts the ZeroMQ listener in a background thread and provides
    a menu-driven interface for the user to interact with syscall policies.

    Args:
        test_mode (bool): If True, the function will exit after one iteration of the loop.
        debug (bool): If True, sets logging to DEBUG level.
    """
    if debug:
        LOGGER.setLevel("DEBUG")
        LOGGER.info("Debug mode is enabled. Logging level set to DEBUG.")
    # Start the ZeroMQ listener in a background thread
    listener_thread = threading.Thread(target=zmq_listener, daemon=True)
    listener_thread.start()
    group_selector.build_syscall_to_group_map("user_tool/groups")
    # LOGGER.info("SYSCALL_TO_GROUP mapping: %s", group_selector.SYSCALL_TO_GROUP)
    # LOGGER.info("Groups structure: %s", group_selector.get_groups_structure("user_tool/groups"))
    # syscall_id = 132
    # group = group_selector.get_group_for_syscall(syscall_id)
    # LOGGER.info("Syscall %d belongs to group: %s", syscall_id, group)
    # group_name = "FileTimestamp"
    # ids = group_selector.get_syscalls_for_group(group_name)
    # LOGGER.info("Syscall IDs for group %s: %s", group_name, ids)

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
    parser = argparse.ArgumentParser(description="User Tool Main")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--test", action="store_true", help="Enable test mode")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level)
    LOGGER.setLevel(log_level)
    for handler in LOGGER.handlers:
        handler.setLevel(log_level)    

    main(test_mode=args.test, debug=args.debug)
