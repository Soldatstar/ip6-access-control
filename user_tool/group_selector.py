import os
import re

GROUPS_ORDER = []  # List to store the order of groups
GROUPS_PARAMETER_ORDER = {}  # Dictionary to store the order of parameters for each group
GROUPS_SYSCALL = {}  # Dictionary to store the system calls for each group
PARAMETERS = {}  # Dictionary to store the parameters
ARGUMENTS = {}  # Dictionary to store the arguments

def parse_file(filename):
    argument_name = None  
    argument_values = []  
    group_name = None  
    syscall_values = []  
    parameter_name = None  
    parameter_values = []  

    with open(filename, 'r') as file:
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
                    GROUPS_PARAMETER_ORDER[group_name].append(parameter_name)
                parameter_name = None 
                parameter_values = [] 
            # Add line to parameter values list
            elif parameter_name:
                parameter_values.append(line)

def get_question(syscall_nr, argument):
    for groups in GROUPS_ORDER:
        for syscall in GROUPS_SYSCALL[groups]:
            # If the current system call matches the given syscall_nr
            if syscall == syscall_nr:
                for parameter in GROUPS_PARAMETER_ORDER[groups]:
                    
                    # Iterate through the arguments for the current parameter
                    counter = 0
                    for arg in PARAMETERS[parameter]:
                        key, value = arg.split("=")
                        value = value.strip()
                        
                        # Check if any of the arguments in ARGUMENTS[value] are present in the given argument array
                        for a in ARGUMENTS[value]:
                            if a in argument:
                              counter += 1
                              break
                          
                    # If the length of the given argument is not 0 and all arguments match
                    if len(argument) != 0 and counter == len(argument):
                        return parameter
                    # If the length of the given argument is 0 and the parameter has no arguments
                    elif len(argument) == 0 and len(PARAMETERS[parameter]) == 0:
                        return parameter 
    
    # If no matching parameter is found, return "-1"
    return "-1"