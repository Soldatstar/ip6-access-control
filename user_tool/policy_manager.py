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
import logging
from shared import conf_utils
POLICIES_DIR = conf_utils.POLICIES_DIR
LOGGER = logging.getLogger("User-Tool")


class Policy:
    """
    Represents a syscall policy decision.
    """

    def __init__(self, path, hash_value, syscall, decision, user="user123", parameter="parameter"):
        self.path = path
        self.name = os.path.basename(path)
        self.hash_value = hash_value
        self.syscall = syscall
        self.decision = decision
        self.user = user
        self.parameter = parameter


def save_decision(policy: Policy, allowed_group=None):
    """
    Save the decision made by the user regarding a syscall policy.

    Args:
        policy (Policy): An instance of the Policy class containing all necessary details.

    This function updates or creates a policy file for the given program
    and saves the user's decision regarding the syscall.
    """
    process_dir = os.path.join(POLICIES_DIR, policy.hash_value)
    os.makedirs(process_dir, exist_ok=True)
    LOGGER.debug(
        "Saving decision for %s (hash: %s) in %s", policy.name, policy.hash_value, process_dir)
    policy_file = os.path.join(process_dir, "policy.json")

    # Handle empty or invalid policy files
    if os.path.exists(policy_file):
        try:
            with open(policy_file, "r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            LOGGER.warning(
                "Policy file %s is empty or invalid. Reinitializing.", policy_file)
            data = None
    else:
        data = None

    # Initialize policy file if it doesn't exist or is invalid
    if data is None:
        data = {
            "metadata": {
                "process_name": policy.name,
                "process_path": policy.path,
                "last_modified": None,
                "approved_by": policy.user
            },
            "rules": {
                "allowed_syscalls": [],
                "denied_syscalls": [],
                "allowed_groups": []
            }
        }

    # Update the policy based on the decision
    syscall_entry = [policy.syscall, policy.parameter]
    if policy.decision == "ALLOW":
        if syscall_entry not in data["rules"]["allowed_syscalls"]:
            data["rules"]["allowed_syscalls"].append(syscall_entry)
        # Add group to allowed_groups if not already present
        if allowed_group and allowed_group not in data["rules"]["allowed_groups"]:
            data["rules"]["allowed_groups"].append(allowed_group)
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

    # Sort the apps list for consistent order
    apps = sorted(os.listdir(POLICIES_DIR))
    if not apps:
        LOGGER.info("No known applications with policies.")
    else:
        LOGGER.info("Known applications with policies:")
        for app in apps:
            policy_file = os.path.join(POLICIES_DIR, app, "policy.json")
            if os.path.exists(policy_file):
                try:
                    with open(policy_file, "r", encoding="UTF-8") as file:
                        data = json.load(file)
                        process_name = data.get("metadata", {}).get(
                            "process_name", "Unknown")
                        LOGGER.info("- %s (Hash: %s)", process_name, app)
                except json.JSONDecodeError:
                    LOGGER.warning("- %s (Invalid policy file)", app)
            else:
                LOGGER.warning("- %s (No policy file found)", app)


def delete_all_policies():
    """
    Delete all existing syscall policies.

    This function removes all policy directories and their contents from the
    policies directory. It logs the status of each deletion attempt.
    """
    if not os.path.exists(POLICIES_DIR):
        LOGGER.info("No policies directory found.")
        return

    for app in sorted(os.listdir(POLICIES_DIR)):  # Sort directory entries
        app_path = os.path.join(POLICIES_DIR, app)
        if os.path.isdir(app_path):
            try:
                shutil.rmtree(app_path)
                LOGGER.info("Deleted policies for %s.", app)
            except OSError as e:
                LOGGER.error(
                    "Failed to delete policies for %s. Error: %s", app, e)

    LOGGER.info("All policies deleted.")
