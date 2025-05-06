import os
import json
import datetime
import shutil

POLICIES_DIR = None
logger = None

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

    apps = sorted(os.listdir(POLICIES_DIR))  # Sort the apps list for consistent order
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