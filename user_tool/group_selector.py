"""
Group Selector module for managing syscall groups and parameters.

This module provides functionality to parse a configuration file, extract syscall groups,
parameters, and arguments, and match syscalls with their corresponding parameters and arguments.
"""

import re
import logging
import os
import sys
import importlib.resources

GROUPS_ORDER = []  # List to store the order of groups
# Dictionary to store the order of parameters for each group
GROUPS_PARAMETER_ORDER = {}
GROUPS_DEFAULT_QUESTION = {} 
# Global mapping from syscall ID to group name
SYSCALL_TO_GROUP = {}
GROUPS_SYSCALL = {}  # Dictionary to store the system calls for each group
PARAMETERS = {}  # Dictionary to store the parameters
ARGUMENTS = {}  # Dictionary to store the arguments
LOGGER = logging.getLogger("User-Tool")

# Global variable to store the resolved groups file path
GROUPS_FILE_PATH = None

def parse_file(filename):
    """
    Parse a configuration file to extract syscall groups, parameters, and arguments.
    """
    def flush_argument(arg_name, arg_values):
        if arg_name and arg_values and arg_name not in ARGUMENTS:
            ARGUMENTS[arg_name] = arg_values[:]

    def flush_parameter(param_name, param_values, group_name):
        if param_name and group_name:
            if param_name not in PARAMETERS:
                PARAMETERS[param_name] = param_values[:]
                if group_name not in GROUPS_PARAMETER_ORDER:
                    GROUPS_PARAMETER_ORDER[group_name] = []
                GROUPS_PARAMETER_ORDER[group_name].append(param_name)

    def flush_group(group_name, syscalls):
        if group_name and syscalls and group_name not in GROUPS_SYSCALL:
            GROUPS_SYSCALL[group_name] = syscalls[:]
            GROUPS_ORDER.append(group_name)

    argument_name, argument_values = None, []
    parameter_name, parameter_values = None, []
    group_name, syscall_values = None, []

    try:
        with open(filename, 'r', encoding="UTF-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                # Argument block
                if line.startswith("a:"):
                    flush_argument(argument_name, argument_values)
                    argument_name = line[2:].strip().split()[0]
                    argument_values = []
                    continue
                elif argument_name and line.startswith(")"):
                    flush_argument(argument_name, argument_values)
                    argument_name, argument_values = None, []
                    continue
                elif argument_name:
                    argument_values.append(line)
                    continue

                # Group block
                if line.startswith("g:"):
                    flush_group(group_name, syscall_values)
                    group_name = line[2:].strip().split()[0]
                    syscall_values = []
                    continue
                elif group_name and line.startswith("}"):
                    flush_group(group_name, syscall_values)
                    group_name, syscall_values = None, []
                    continue
                elif group_name and line and line[0].isdigit():
                    syscall_values.append(int(line.split()[0]))
                    continue

                # Default question for group
                if group_name and line.startswith("d:"):
                    GROUPS_DEFAULT_QUESTION[group_name] = line[2:].strip()
                    continue

                # Parameter block
                if line.startswith("p:"):
                    flush_parameter(parameter_name, parameter_values, group_name)
                    parameter_name = line[2:].split('?')[0].strip()
                    parameter_values = []
                    continue
                elif parameter_name and group_name and line.startswith("]"):
                    flush_parameter(parameter_name, parameter_values, group_name)
                    parameter_name, parameter_values = None, []
                    continue
                elif parameter_name:
                    parameter_values.append(line)
                    continue

        # Final flushes in case file ends without closing blocks
        flush_argument(argument_name, argument_values)
        flush_parameter(parameter_name, parameter_values, group_name)
        flush_group(group_name, syscall_values)

        LOGGER.debug("Group para. order: %s", GROUPS_PARAMETER_ORDER)
    except (FileNotFoundError, IOError, ValueError) as e:
        LOGGER.error("Error parsing file %s: %s", filename, e)


def get_question(syscall_nr, argument):
    """
    Get the parameter question for a given syscall and its arguments.

    Args:
        syscall_nr (int): Number of the syscall.
        argument (list): Arguments of the syscall.

    Returns:
        str: The parameter question if found, otherwise -1.
    """
    for groups in GROUPS_ORDER:
        LOGGER.debug("Processing group: %s", groups)
        
        for syscall in GROUPS_SYSCALL[groups]:
            LOGGER.debug("Checking syscall: %s against target: %s", syscall, syscall_nr)
            
            if syscall == syscall_nr:
                LOGGER.info("Match found! Syscall %s matches target %s", syscall, syscall_nr)
                
                # If the group has no parameters, return the default question
                param_order = GROUPS_PARAMETER_ORDER.get(groups, [])
                if not param_order:
                    default_question = GROUPS_DEFAULT_QUESTION.get(groups, -1)
                    LOGGER.debug("No parameters for group '%s', returning default: %s", groups, default_question)
                    return default_question

                for parameter in param_order:
                    LOGGER.debug("Processing parameter: %s", parameter)
                    parameter_values = set()
                    for arg in PARAMETERS[parameter]:
                        LOGGER.debug("Processing argument: %s", arg)
                        key, value = arg.split("=")
                        value = value.strip()
                        LOGGER.debug("Parsed key: %s, value: %s", key, value)
                        for a in ARGUMENTS[value]:
                            parameter_values.add(a)
                            LOGGER.debug("Added to parameter_values: %s", a)
                    LOGGER.debug("Parameter '%s' has values: %s", parameter, parameter_values)
                    LOGGER.debug("Checking against provided argument: %s", argument)
                    if argument and parameter_values.issuperset(set(argument)):
                        LOGGER.info("SUCCESS: Non-empty argument %s is subset of %s", argument, parameter_values)
                        LOGGER.info("Returning parameter: %s", parameter)
                        return parameter
                    elif len(argument) == 0 and not parameter_values:
                        LOGGER.info("SUCCESS: Empty argument matches empty parameter_values")
                        LOGGER.info("Returning parameter: %s", parameter)
                        return parameter
                    else:
                        if len(argument) != 0:
                            LOGGER.warning("MISMATCH: Argument %s not subset of %s", argument, parameter_values)
                        else:
                            LOGGER.warning("MISMATCH: Empty argument but parameter has values: %s", parameter_values)
                default_question = GROUPS_DEFAULT_QUESTION.get(groups, -1)
                LOGGER.warning("No parameter matched, returning default: %s", default_question)
                return default_question            
            else:
                LOGGER.debug("No match: %s != %s", syscall, syscall_nr)

    LOGGER.warning("No matching parameter found across all groups")
    return -1


def argument_separator(argument_raw, argument_pretty):
    """
    Separate syscall arguments from their formatted strings.

    Args:
        argument_raw (list): Raw arguments of the syscall.
        argument_pretty (list): Formatted arguments of the syscall.

    Returns:
        argument_values: Extracted arguments for question picking
        argument_values_no_filter: Extracted arguments only for user information
    """
    argument_values = []
    argument_values_no_filter = []
    para_type_file = ["[filename]", "[pathname]", "[oldname]", "[old]", "[path]"]
    para_type = ["[flags]", "[domain]", "[type]"]

    for i, raw_value in enumerate(argument_raw):
        if raw_value != "*":
            pretty_value = argument_pretty[i]

            if any(keyword in pretty_value for keyword in para_type_file):
                # Extract the filename value and add it to argument values
                filename_value = pretty_value.split("[")[0].strip("'")
                if filename_value != '':
                    argument_values_no_filter.append(filename_value)
            elif any(keyword in pretty_value for keyword in para_type):
                # Split the flags by '|'
                parts = pretty_value.split("[")[0].split('|')

                # Cut all digits that are not A-Z or _
                def clean_part(part):
                    cleaned = re.sub(r'[^A-Z_]', '', part)
                    return cleaned

                flag_mode_values = [clean_part(
                    part) for part in parts if clean_part(part) != '']
                argument_values.extend(flag_mode_values)

    return argument_values, argument_values_no_filter



def parse_groups_file(filename: str) -> dict:
    """
    Parse the groups file and return a dict mapping group names to syscall IDs.
    """
    groups = {}
    current_group = None
    syscalls = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith("g:"):
                if current_group and syscalls:
                    groups[current_group] = syscalls
                current_group = line[2:].split("{")[0].strip()
                syscalls = []
            elif current_group and line and line[0].isdigit():
                syscall_id = int(line.split()[0])
                syscalls.append(syscall_id)
            elif line.startswith("}"):
                if current_group and syscalls:
                    groups[current_group] = syscalls
                current_group = None
                syscalls = []
        if current_group and syscalls:
            groups[current_group] = syscalls
    return groups

def build_syscall_to_group_map(groups_file: str):
    """
    Build a global mapping from syscall ID to group name.
    """
    global SYSCALL_TO_GROUP, GROUPS_FILE_PATH
    SYSCALL_TO_GROUP.clear()
    
    # Try to handle both development and installed environments
    if not os.path.exists(groups_file):
        try:
            # For Python 3.9+
            with importlib.resources.path('user_tool', 'groups') as path:
                groups_file = str(path)
        except (ImportError, ModuleNotFoundError, FileNotFoundError):
            # Fallback approaches
            package_dir = os.path.dirname(__file__)
            possible_paths = [
                os.path.join(package_dir, 'groups'),
                os.path.join(os.path.dirname(package_dir), 'user_tool', 'groups')
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    groups_file = path
                    break
    
    # Store the resolved groups file path for later use
    GROUPS_FILE_PATH = groups_file
    LOGGER.debug(f"Using groups file: {GROUPS_FILE_PATH}")
    
    group_map = parse_groups_file(groups_file)
    for group, syscalls in group_map.items():
        for syscall in syscalls:
            SYSCALL_TO_GROUP[syscall] = group

def get_group_for_syscall(syscall_id: int):
    """
    Return the group name for a given syscall ID, or None if not found.
    """
    return SYSCALL_TO_GROUP.get(syscall_id)

def get_groups_structure(filename: str) -> dict:
    """
    Return a dict mapping group names to syscall IDs.
    """
    return parse_groups_file(filename)

def get_syscalls_for_group(group_name: str, groups_file: str = None):
    """
    Return a list of syscall IDs for a given group name.
    
    Args:
        group_name (str): The name of the group to get syscalls for
        groups_file (str, optional): Path to the groups file. If None, uses the globally resolved path
        
    Returns:
        list: List of syscall IDs belonging to the specified group
    """
    # Use the globally resolved path if available and no path was provided
    if groups_file is None:
        if GROUPS_FILE_PATH:
            groups_file = GROUPS_FILE_PATH
        else:
            # Fall back to the default path if no global path is set
            # (This should rarely happen as build_syscall_to_group_map should be called first)
            groups_file = "user_tool/groups"
            LOGGER.warning("No groups file path set, falling back to default: %s", groups_file)
    
    groups = parse_groups_file(groups_file)
    return groups.get(group_name, [])