"""
Module to manage syscall policies for applications.

This module provides functionality to:
- Save user decisions regarding syscall policies.
- List applications with existing policies.
- Delete all existing policies.
"""

import os
import json
import datetime
import shutil

POLICIES_DIR = None
LOGGER = None

def save_decision(
    program_path: str,
    program_hash: str,
    syscall_nr: int,
    decision: str,
    user: str = "user123",
    parameter: str = "parameter",
):
    """
    Save the decision made by the user regarding a syscall policy.

    Args:
        program_path (str): The file path of the program.
        program_hash (str): The hash of the program for unique identification.
        syscall_nr (int): The syscall number.
        decision (str): The decision made by the user ("ALLOW" or "DENY").
        user (str): The user making the decision. Defaults to "user123".
        parameter (str): Additional parameter information. Defaults to "parameter".

    This function updates or creates a policy file for the given program
    and saves the user's decision regarding the syscall.
    """
    program_name = os.path.basename(program_path)
    process_dir = os.path.join(POLICIES_DIR, program_hash)
    os.makedirs(process_dir, exist_ok=True)
    LOGGER.info(f"Saving decision for {program_name} (hash: {program_hash}) in {process_dir}")
    policy_file = os.path.join(process_dir, "policy.json")

    # Handle empty or invalid policy files
    if os.path.exists(policy_file):
        try:
            with open(policy_file, "r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            LOGGER.warning(f"Policy file {policy_file} is empty or invalid. Reinitializing.")
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
    with open(policy_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def list_known_apps():
    """
    List all applications with known syscall policies.

    This function scans the policies directory and logs the names of applications
    with existing policies. It also handles cases where the policy file is missing
    or invalid.
    """
    if not os.path.exists(POLICIES_DIR):
        LOGGER.info("No policies directory found.")
        return

    apps = sorted(os.listdir(POLICIES_DIR))  # Sort the apps list for consistent order
    if not apps:
        LOGGER.info("No known applications with policies.")
    else:
        LOGGER.info("Known applications with policies:")
        for app in apps:
            policy_file = os.path.join(POLICIES_DIR, app, "policy.json")
            if os.path.exists(policy_file):
                try:
                    with open(policy_file, "r",encoding="UTF-8") as file:
                        data = json.load(file)
                        process_name = data.get("metadata", {}).get("process_name", "Unknown")
                        LOGGER.info(f"- {process_name} (Hash: {app})")
                except json.JSONDecodeError:
                    LOGGER.warning(f"- {app} (Invalid policy file)")
            else:
                LOGGER.warning(f"- {app} (No policy file found)")

def delete_all_policies():
    """
    Delete all existing syscall policies.

    This function removes all policy directories and their contents from the
    policies directory. It logs the status of each deletion attempt.
    """
    if not os.path.exists(POLICIES_DIR):
        LOGGER.info("No policies directory found.")
        return

    for app in os.listdir(POLICIES_DIR):
        app_path = os.path.join(POLICIES_DIR, app)
        if os.path.isdir(app_path):
            try:
                shutil.rmtree(app_path)
                LOGGER.info(f"Deleted policies for {app}.")
            except OSError as e:
                LOGGER.error(f"Failed to delete policies for {app}. Error: {e}")

    LOGGER.info("All policies deleted.")
