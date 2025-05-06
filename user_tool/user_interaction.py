import tkinter as tk
import threading
import queue
import select
import sys

def ask_permission(syscall_nr, program_name, program_hash, parameter_formated, logger):
    """
    Prompt the user for permission to allow or deny a syscall operation.

    This function provides both a graphical user interface (GUI) and a command-line
    interface (CLI) for the user to make a decision regarding a syscall operation.
    The decision can be "ALLOW", "DENY", or "ONE_TIME". The GUI and CLI run
    concurrently, and the first decision made by the user is returned.

    Args:
        syscall_nr (int): The syscall number being requested.
        program_name (str): The name of the program requesting the syscall.
        program_hash (str): A unique hash representing the program.
        parameter_formated (str): A formatted string of the syscall parameters.
        logger (logging.Logger): A logger instance for logging messages.

    Returns:
        str: The user's decision, which can be "ALLOW", "DENY", or "ONE_TIME".
    """
    decision = {'value': None}
    q = queue.Queue()
    after_id = None

    def set_decision(choice):
        nonlocal after_id
        if decision['value'] is None:
            decision['value'] = choice
            q.put(choice)  # Ensure the decision is added to the queue for consistency
            if after_id is not None:
                try:
                    root.after_cancel(after_id)
                except tk.TclError:
                    pass
            if root.winfo_exists():  # Ensure root exists before attempting to destroy
                root.destroy()

    def ask_cli():
        prompt = (
            f"Allow operation for syscall {syscall_nr}?\n"
            f"            Program: {program_name}\n"
            f"            Hash: {program_hash}\n"
            #f"            Parameter: {parameter_formated}\n"
            "             ( (y)es / (n)o / (o)ne ): "
        )
        mapping = {
            'yes': 'ALLOW',   'y': 'ALLOW',
            'no':  'DENY',    'n': 'DENY',
            'one': 'ONE_TIME','o': 'ONE_TIME',
        }

        logger.info(prompt)

        while decision['value'] is None:
            r, _, _ = select.select([sys.stdin], [], [], 4.0)
            if r:
                ans = sys.stdin.readline().strip().lower()
                choice = mapping.get(ans)
                if choice:
                    q.put(choice)
                    break

    def poll_queue():
        nonlocal after_id
        try:
            choice = q.get_nowait()
        except queue.Empty:
            after_id = root.after(100, poll_queue)
        else:
            set_decision(choice)

    root = tk.Tk()
    root.title("Permission Request")

    text_width = max(len(program_name), len(program_hash)) * 7
    width = max(400, text_width + 50)
    height = 150 + 50

    root.geometry(f"{width}x{height}")

    lbl = tk.Label(
        root,
        text=(
            f"Allow operation for syscall {syscall_nr}?\n"
            f"Program: {program_name}\n"
            f"Hash: {program_hash}\n"
            #f"Parameter: {parameter_formated}"
        ),
        wraplength=350
    )
    lbl.pack(pady=20)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)
    for txt, val in [("Allow", "ALLOW"), ("Deny", "DENY"), ("One Time", "ONE_TIME")]:
        tk.Button(btn_frame, text=txt, width=10,
                  command=lambda v=val: set_decision(v)).pack(side=tk.LEFT, padx=5)

    threading.Thread(target=ask_cli, daemon=True).start()
    after_id = root.after(100, poll_queue)

    root.mainloop()
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
