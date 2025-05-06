import os
import re

FILE_NAME = "groups"
GROUPS_ORDER = []
GROUPS_PARAMETER_ORDER = []
GROUPS_SYSCALL = {}
PARAMETERS = {}
ARGUMENTS = {}

def parse_args():
    argument_name = None
    argument_values = []

    with open(FILE_NAME, 'r') as file:
        for line in file:
            line = line.strip()
            
            if not line:
                continue

            if line.startswith("a:"):
                argument_name = line[2:].strip().split()[0]
            
            elif argument_name and line.startswith("}"):
                
                if argument_name not in ARGUMENTS:
                    ARGUMENTS[argument_name] = argument_values
                
                argument_name = None
                argument_values = []
            
            elif argument_name:
                argument_values.append(line)

def parse_groups():
    group_name = None
    syscall_values = []

    with open(FILE_NAME, 'r') as file:
        for line in file:
            line = line.strip()
            
            if not line:
                continue
            
            match_nr = re.match(r'(\d+)', line)

            if line.startswith("g:"):
                group_name = line[2:].strip().split()[0]

            elif group_name and line.startswith("}"):
                
                if group_name not in GROUPS_SYSCALL:
                    GROUPS_SYSCALL[group_name] = syscall_values
                    GROUPS_ORDER.append(group_name)
                
                group_name = None
                syscall_values = []
            
            elif group_name and match_nr:
                number = int(match_nr.group(1))
                syscall_values.append(number)

def parse_parameters():
    parameter_name = None
    parameter_values = []

    with open(FILE_NAME, 'r') as file:
        for line in file:
            line = line.strip()
            
            if not line:
                continue
            
            if line.startswith("p:"):
                line = line.split('?')[0]
                parameter_name = line[2:].strip()

            elif parameter_name and line.startswith("}"):
                if parameter_name not in PARAMETERS:
                    PARAMETERS[parameter_name] = parameter_values
                    GROUPS_PARAMETER_ORDER.append(parameter_name)
                
                parameter_name = None
                parameter_values = []

            elif parameter_name:
                parameter_values.append(line)

if __name__ == "__main__":
    if os.path.exists(FILE_NAME):
        parse_args()
        parse_groups()
        parse_parameters()
        
        print(GROUPS_ORDER)
        print(GROUPS_PARAMETER_ORDER)
        print(GROUPS_SYSCALL)
        print(PARAMETERS)
        print(ARGUMENTS)

    else:
        print(f"File {FILE_NAME} not found")
