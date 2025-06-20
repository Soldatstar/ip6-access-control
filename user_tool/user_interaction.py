import tkinter as tk
import threading
import queue
import select
import sys
import logging
from user_tool import group_selector

GROUP_FILE = "user_tool/groups"
LOGGER = logging.getLogger("User-Tool")
def ask_permission(syscall_nr, syscall_name, program_name, program_hash,
                   parameter_formated, parameter_raw):

    # Prepare question text
    group_selector.parse_file(filename=GROUP_FILE)
    args, args_no_filter = group_selector.argument_separator(
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
    # Determine group and syscalls in group
    group = group_selector.get_group_for_syscall(syscall_nr)
    syscalls_in_group = []
    if group:
        syscalls_in_group = group_selector.get_syscalls_for_group(group)

    # Build text
    text = (
        f"{question}?\n\n"
        f"Program: {program_name}\n"
    )
    # Insert group info if available
    if group:
        text += f"Group: {group}\n"
    else:
        text += "Group: (none)\n"
    text += f"Systemcall: {syscall_name}\n"

    if args or args_no_filter:
        text += f"Parameter: {', '.join(args_no_filter + args)}\n"
        


    # Build the GUI
    root = tk.Tk()
    root.title("Permission Request")
    width = max(500, len(parameter_formated)*7 + 250)
    root.geometry(f"{width}x400")

    #color scheme
    BG_COLOR = "#2E2E2E"
    FG_COLOR = "#F0F0F0"
    BTN_BG = "#4A4A4A"
    BTN_ACTIVE_BG = "#5A5A5A"
    ACCENT_COLOR = "#007ACC"
    DENY_BTN_BG = "#8B3A3A"
    DENY_BTN_ACTIVE_BG = "#A14444"

    root.config(bg=BG_COLOR)

    tk.Label(
        root,
        text=text,
        wraplength=width-50,
        bg=BG_COLOR, fg=FG_COLOR, font=("Arial", 12)
    ).pack(pady=20)

    main_btn_frame = tk.LabelFrame(root, text="Decision", padx=10, pady=10,
                                   bg=BG_COLOR, fg=FG_COLOR, font=("Arial", 10, "bold"))
    main_btn_frame.pack(pady=(0, 10))

    btn_texts = [
        ("Always allow this action", "ALLOW_THIS"),
        ("Always allow for this group", "ALLOW"),
        ("Allow this action once", "ONE_TIME"),
        ("Deny", "DENY"),
    ]
    btn_widgets = []
    for txt, val in btn_texts:
        btn_bg = DENY_BTN_BG if val == "DENY" else BTN_BG
        btn_active_bg = DENY_BTN_ACTIVE_BG if val == "DENY" else BTN_ACTIVE_BG
        btn = tk.Button(
            main_btn_frame, text=txt, width=22,
            command=lambda v=val: set_decision(v),
            bg=btn_bg, fg=FG_COLOR, activebackground=btn_active_bg,
            activeforeground=FG_COLOR, relief=tk.FLAT, font=("Arial", 10)
        )
        btn_widgets.append(btn)

    for i, btn in enumerate(btn_widgets):
        btn.grid(row=i//2, column=i%2, padx=5, pady=4, sticky="ew")

    group_descriptions = {}
    try:
        import os
        current_group = None
        with open(GROUP_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("g:"):
                    current_group = line[2:].split("{")[0].strip()
                elif current_group and line.startswith("desc:"):
                    group_descriptions[current_group] = line[5:].strip()
                elif line.startswith("}"):
                    current_group = None
    except Exception:
        pass

    def show_group_syscalls():
        if not group:
            tk.messagebox.showinfo("Group Info", "No group found for this syscall.")
            return
        win = tk.Toplevel(root)
        win.title(f"Group: {group}")
        win.geometry("500x400")
        win.config(bg=BG_COLOR)
        desc = group_descriptions.get(group, "")
        if desc:
            tk.Label(win, text=desc, font=("Arial", 11, "italic"), wraplength=450, justify="left", bg=BG_COLOR, fg=FG_COLOR).pack(pady=(10, 5))
        else:
            # Show placeholder if no description is available
            tk.Label(win, text="No description available for this group.", font=("Arial", 11, "italic"), fg="gray", wraplength=450, justify="left", bg=BG_COLOR).pack(pady=(10, 5))
        tk.Label(win, text=f"Group: {group}", font=("Arial", 14, "bold"), bg=BG_COLOR, fg=FG_COLOR).pack(pady=5)
        tk.Label(win, text="Syscalls in this group:", font=("Arial", 12), bg=BG_COLOR, fg=FG_COLOR).pack()
        listbox = tk.Listbox(win, width=60, bg=BTN_BG, fg=FG_COLOR, selectbackground=ACCENT_COLOR, relief=tk.FLAT, highlightthickness=0)
        for scid in syscalls_in_group:
            listbox.insert(tk.END, f"{scid}")
        listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        tk.Button(win, text="Close", command=win.destroy, bg=BTN_BG, fg=FG_COLOR, activebackground=BTN_ACTIVE_BG, activeforeground=FG_COLOR, relief=tk.FLAT).pack(pady=5)

    info_frame = tk.Frame(root, bg=BG_COLOR)
    info_frame.pack(pady=(0, 10))
    info_btn = tk.Button(
        info_frame, text="Show Group information", width=18,
        command=show_group_syscalls, relief=tk.FLAT, fg=ACCENT_COLOR, cursor="hand2",
        bg=BG_COLOR, activebackground=BG_COLOR, activeforeground=ACCENT_COLOR
    )
    info_btn.pack()
    info_btn.config(font=("Arial", 9, "underline"))


    root.createfilehandler(sys.stdin, tk.READABLE, on_stdin)

    # Run until either a button or stdin choice destroys root
    text += "    (y)es / (t)his / (n)o / (o)ne: "
    
    prompt = text
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
