import os

FILE_NAME = "groups"
ARGUMENTS = {}

def parse_args():
    argument_name = None
    argument_values = []

    with open(FILE_NAME, 'r') as file:
        for line in file:
            
            # Strip leading and ending withspaces
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue

            # New argument name
            if line.startswith("a:"):
                argument_name = line[2:].strip().split()[0]

            # Close entry when "}" appears
            elif argument_name and line.startswith("}"):
                ARGUMENTS[argument_name] = argument_values
                argument_name = None
                argument_values = []
            
            # New entry for argument
            elif argument_name:
                argument_values.append(line)

if __name__ == "__main__":
    if os.path.exists(FILE_NAME):
        parse_args()
        print(ARGUMENTS)
    else:
        print(f"File {FILE_NAME} not found")
