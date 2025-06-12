"""
Group Selector module for managing syscall groups and parameters.

This module provides functionality to parse a configuration file, extract syscall groups,
parameters, and arguments, and match syscalls with their corresponding parameters and arguments.
"""

import re
import logging
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

def parse_file(filename):
    """
    Parse a configuration file to extract syscall groups, parameters, and arguments.

    Args:
        filename (str): Path to the configuration file.
    """
    argument_name = None
    argument_values = []
    group_name = None
    syscall_values = []
    parameter_name = None
    parameter_values = []
    try:
        with open(filename, 'r', encoding="UTF-8") as file:
            LOGGER.info("Parsing groups file: %s", filename)
            for line in file:
                # Remove leading/trailing whitespace
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Extract argument name

                if group_name and line.startswith("d:"):
                    default_question = line[2:].strip()
                    GROUPS_DEFAULT_QUESTION[group_name] = default_question
                    continue  # Skip further processing for this line
                if line.startswith("a:"):
                    argument_name = line[2:].strip().split()[0]
                # Store argument values
                elif argument_name and line.startswith(")"):
                    if argument_name not in ARGUMENTS:
                        ARGUMENTS[argument_name] = argument_values
                    argument_name = None
                    argument_values = []
                # Add line to argument values list
                elif argument_name:
                    argument_values.append(line)

                match_nr = re.match(r'(\d+)', line)
                # Extract group name
                if line.startswith("g:"):
                    group_name = line[2:].strip().split()[0]
                # Store system call values
                elif group_name and line.startswith("}"):
                    if group_name not in GROUPS_SYSCALL:
                        GROUPS_SYSCALL[group_name] = syscall_values
                        GROUPS_ORDER.append(group_name)
                    group_name = None
                    syscall_values = []
                # Add system call number to the list
                elif group_name and match_nr:
                    number = int(match_nr.group(1))
                    syscall_values.append(number)

                # Extract parameter name
                if line.startswith("p:"):
                    line = line.split('?')[0]
                    parameter_name = line[2:].strip()
                # Initialize parameter order list for the group
                elif parameter_name and group_name and line.startswith("]"):
                    LOGGER.info("initializing group: %s",group_name)
                    if parameter_name not in PARAMETERS:
                        if group_name not in GROUPS_PARAMETER_ORDER:
                            GROUPS_PARAMETER_ORDER[group_name] = []
                        PARAMETERS[parameter_name] = parameter_values
                        GROUPS_PARAMETER_ORDER[group_name].append(
                            parameter_name)
                    parameter_name = None
                    parameter_values = []
                # Add line to parameter values list
                elif parameter_name:
                    parameter_values.append(line)
        LOGGER.info("Group para. order: %s",GROUPS_PARAMETER_ORDER)               
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
        LOGGER.info("Processing group: %s", groups)
        
        for syscall in GROUPS_SYSCALL[groups]:
            LOGGER.info("Checking syscall: %s against target: %s", syscall, syscall_nr)
            
            # If the current system call matches the given syscall_nr
            if syscall == syscall_nr:
                LOGGER.info("Match found! Syscall %s matches target %s", syscall, syscall_nr)
                
                for parameter in GROUPS_PARAMETER_ORDER[groups]:
                    LOGGER.info("Processing parameter: %s", parameter)
                    parameter_values = set()
                    
                    # Iterate through the arguments for the current parameter
                    for arg in PARAMETERS[parameter]:
                        LOGGER.debug("Processing argument: %s", arg)
                        key, value = arg.split("=")
                        value = value.strip()
                        LOGGER.debug("Parsed key: %s, value: %s", key, value)
                        
                        # Add entry to the parameter set
                        for a in ARGUMENTS[value]:
                            parameter_values.add(a)
                            LOGGER.debug("Added to parameter_values: %s", a)
                    
                    LOGGER.info("Parameter '%s' has values: %s", parameter, parameter_values)
                    LOGGER.info("Checking against provided argument: %s", argument)
                    
                    # If the rule has required values, check if the syscall's arguments contain all of them.
                    if parameter_values and set(argument).issuperset(parameter_values):
                        LOGGER.info("SUCCESS: Non-empty argument %s is subset of %s", argument, parameter_values)
                        LOGGER.info("Returning parameter: %s", parameter)
                        return parameter
                        
                    # If the length of the given argument is 0 and the parameter has no arguments
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
    # If no matching parameter is found, return -1
    return -1


def argument_separator(argument_raw, argument_pretty):
    """
    Separate syscall arguments from their formatted strings.

    Args:
        argument_raw (list): Raw arguments of the syscall.
        argument_pretty (list): Formatted arguments of the syscall.

    Returns:
        list: Extracted arguments.
    """
    argument_values = []

    for i, raw_value in enumerate(argument_raw):
        if raw_value != "*":
            pretty_value = argument_pretty[i]

            # Check if the argument is from type filename
            if "[filename]" in pretty_value:
                # Extract the filename value and add it to argument values
                filename_value = pretty_value.split("[")[0].strip("'")
                if filename_value != '':
                    argument_values.append(filename_value)

            # Check if the argument is from type flags or mode
            elif "[flags]" in pretty_value or "[mode]" in pretty_value:
                # Split the flags by '|'
                parts = pretty_value.split("[")[0].split('|')

                # Cut all digits that are not A-Z or _
                def clean_part(part):
                    cleaned = re.sub(r'[^A-Z_]', '', part)
                    return cleaned

                flag_mode_values = [clean_part(
                    part) for part in parts if clean_part(part) != '']
                argument_values.extend(flag_mode_values)

    return argument_values



def build_syscall_to_group_map(groups_file):
    """
    Build a global mapping from syscall ID to group name.
    """
    global SYSCALL_TO_GROUP
    group_map = get_groups_structure(groups_file)
    SYSCALL_TO_GROUP = {}
    for group, syscalls in group_map.items():
        for syscall in syscalls:
            SYSCALL_TO_GROUP[syscall] = group

def get_group_for_syscall(syscall_id):
    """
    Return the group name for a given syscall ID, or None if not found.
    """
    return SYSCALL_TO_GROUP.get(syscall_id)

def get_groups_structure(filename):
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
        # Add last group if file doesn't end with }
        if current_group and syscalls:
            groups[current_group] = syscalls
    return groups


def get_syscalls_for_group(group_name, groups_file="user_tool/groups"):
    """
    Return a list of syscall IDs for a given group name.
    """
    groups = get_groups_structure(groups_file)
    return groups.get(group_name, [])