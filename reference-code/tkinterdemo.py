import tkinter as tk
from tkinter import messagebox
import queue


def show_popup(syscall_nr, program_name, program_hash):
    """Show a popup asking for user permission."""
    decision = None  

    def on_allow():
        nonlocal decision  
        decision = "ALLOW"
        root.destroy()

    def on_deny():
        nonlocal decision  
        decision = "DENY"
        root.destroy()

    def on_one_time():
        nonlocal decision  
        decision = "ONE_TIME"
        root.destroy()

    root = tk.Tk()
    root.title("Permission Request")
    root.geometry("400x150")

    label = tk.Label(root, text=f"Allow operation for syscall {syscall_nr}?\n"
                                f"Program: {program_name}\n"
                                f"Hash: {program_hash}", wraplength=350)
    label.pack(pady=20)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    allow_button = tk.Button(button_frame, text="Allow", command=on_allow, width=10)
    allow_button.pack(side=tk.LEFT, padx=10)

    deny_button = tk.Button(button_frame, text="Deny", command=on_deny, width=10)
    deny_button.pack(side=tk.RIGHT, padx=10)

    one_time_button = tk.Button(button_frame, text="One Time", command=on_one_time, width=10)
    one_time_button.pack(side=tk.RIGHT, padx=10)

    root.mainloop()
    return decision

if __name__ == "__main__":
    syscall_nr = 123
    program_name = "example_program"
    program_hash = "abc123hash"

    decision = show_popup(syscall_nr, program_name, program_hash)
    print(f"User decision: {decision}")