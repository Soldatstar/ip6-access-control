import tkinter as tk
import threading
import queue
import select
import sys
import logging
from user_tool import group_selector

# Configuration file for the syscall conversion with parameters for the appropriate question.
GROUP_FILE = "user_tool/groups"
LOGGER = logging.getLogger("User-Tool")
def ask_permission(syscall_nr, program_name, program_hash,
                   parameter_formated, parameter_raw):

    # Prepare question text
    group_selector.parse_file(filename=GROUP_FILE)
    args = group_selector.argument_separator(
        argument_raw=parameter_raw,
        argument_pretty=parameter_formated
    )
    question = group_selector.get_question(
        syscall_nr=syscall_nr, argument=args
    )
    if question == -1:
        question = f"Allow operation for syscall {syscall_nr}"
    LOGGER.info("Question: %s", question)

    decision = {'value': None}
    def set_decision(choice):
        if decision['value'] is None:
            decision['value'] = choice
            # immediately tear down everything
            try:
                root.deletefilehandler(sys.stdin)
            except Exception:
                pass
            root.destroy()

    # CLI‑mapping via stdin
    mapping = {
        'yes': 'ALLOW',   'y': 'ALLOW',
        'this': 'ALLOW_THIS', 't': 'ALLOW_THIS',
        'no':  'DENY',    'n': 'DENY',
        'one': 'ONE_TIME','o': 'ONE_TIME',
    }
    def on_stdin(_, mask):
        """Called in the mainloop when stdin is readable."""
        line = sys.stdin.readline()
        if not line:
            return
        key = line.strip().lower()
        choice = mapping.get(key)
        if choice:
            set_decision(choice)

    # Build the GUI
    root = tk.Tk()
    root.title("Permission Request")
    width = max(400, len(parameter_formated)*7 + 150)
    root.geometry(f"{width}x200")

    tk.Label(
        root,
        text=(
            f"{question}?\n"
            f"Program: {program_name}\n"
            f"Parameter: {parameter_formated}"
        ),
        wraplength=width-50
    ).pack(pady=20)

    btn_frame = tk.Frame(root)
    btn_frame.pack()
    for txt, val in [
        ("Allow (Group)", "ALLOW"),
        ("Allow Only This", "ALLOW_THIS"),
        ("Deny", "DENY"),
        ("One Time", "ONE_TIME")
    ]:
        tk.Button(
            btn_frame, text=txt, width=15,
            command=lambda v=val: set_decision(v)
        ).pack(side=tk.LEFT, padx=5)

    # Tell Tk to watch stdin in the mainloop
    root.createfilehandler(sys.stdin, tk.READABLE, on_stdin)

    # Run until either a button or stdin choice destroys root

    prompt = (
        f"{question}?\n"
        f"    Program: {program_name}\n"
        f"    Parameter: {parameter_formated}\n"
        "    (y)es / (t)his / (n)o / (o)ne: "
    )
    print(prompt, end="", flush=True)

    root.mainloop()
    LOGGER.info("User decision: %s", decision['value'])
    return decision['value']

def non_blocking_input(prompt: str, timeout: float = 0.5) -> str:
    """
    Prompt the user for input without blocking indefinitely.

    This function displays a prompt to the user and waits for input for a specified
    timeout period. If the user provides input within the timeout, it is returned.
    Otherwise, the function returns None.

    Args:
        prompt (str): The message to display to the user.
        timeout (float): The maximum time (in seconds) to wait for input. Defaults to 0.5 seconds.

    Returns:
        str: The user's input if provided within the timeout, or None if no input is received.
    """
    print(prompt, end='', flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    return None
