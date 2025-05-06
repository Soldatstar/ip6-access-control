import os
import re

FILE_NAME = "groups"
GROUPS_ORDER = []  # List to store the order of groups
GROUPS_PARAMETER_ORDER = {}  # Dictionary to store the order of parameters for each group
GROUPS_SYSCALL = {}  # Dictionary to store the system calls for each group
PARAMETERS = {}  # Dictionary to store the parameters
ARGUMENTS = {}  # Dictionary to store the arguments

def parse_file():
    argument_name = None  
    argument_values = []  
    group_name = None  
    syscall_values = []  
    parameter_name = None  
    parameter_values = []  

    with open(FILE_NAME, 'r') as file:
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

if __name__ == "__main__":
    if os.path.exists(FILE_NAME):
        parse_file()
        
        print(GROUPS_ORDER)
        print(GROUPS_PARAMETER_ORDER)
        print(GROUPS_SYSCALL)
        print(PARAMETERS)
        print(ARGUMENTS)

    else:
        print(f"File {FILE_NAME} not found")
