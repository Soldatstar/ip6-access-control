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
        for syscall in GROUPS_SYSCALL[groups]:
            # If the current system call matches the given syscall_nr
            if syscall == syscall_nr:
                for parameter in GROUPS_PARAMETER_ORDER[groups]:
                    
                    parameter_values = set()
                    # Iterate through the arguments for the current parameter
                    for arg in PARAMETERS[parameter]:
                        key, value = arg.split("=")
                        value = value.strip()
                        
                        # Add entry to the parameter set
                        for a in ARGUMENTS[value]:
                            parameter_values.add(a)
                          
                    # If the length of the given argument is not 0 and all given arguments match the parameter set
                    if len(argument) != 0 and set(argument).issubset(parameter_values):
                        return parameter
                    # If the length of the given argument is 0 and the parameter has no arguments
                    elif len(argument) == 0 and not parameter_values:
                        return parameter 
    
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
