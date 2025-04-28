import threading
import tkinter as tk
from tkinter import messagebox

def show_permission(syscall_nr, program_name, program_hash):
    # TODO: implement into user-tool
    decision = {'value': None}  

    def set_decision(choice):
        if decision['value'] is None:
            decision['value'] = choice
            root.destroy()  

    def ask_cli():
        prompt = (
            f"\nAllow operation for syscall {syscall_nr}?\n"
            f"Program: {program_name}\n"
            f"Hash: {program_hash}\n"
            "( (y)es / (n)o / (o)ne ): "
        )
        ans = input(prompt).strip().lower()

        mapping = {
            'yes'   :   'ALLOW',
            'y'     :   'ALLOW',
            'no'    :   'DENY',
            'n'     :   'DENY',
            'one'   :   'ONE_TIME',
            'o'     :   'ONE_TIME',
        }

        choice = mapping.get(ans)
        if choice:
            root.after(0, lambda: set_decision(choice))

    root = tk.Tk()
    root.title("Permission Request")
    root.geometry("400x150")

    lbl = tk.Label(
        root,
        text=(
            f"Allow operation for syscall {syscall_nr}?\n"
            f"Program: {program_name}\n"
            f"Hash: {program_hash}"
        ),
        wraplength=350
    )
    lbl.pack(pady=20)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Allow", width=10,
              command=lambda: set_decision("ALLOW")).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Deny", width=10,
              command=lambda: set_decision("DENY")).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="One Time", width=10,
              command=lambda: set_decision("ONE_TIME")).pack(side=tk.LEFT, padx=5)

    cli_thread = threading.Thread(target=ask_cli, daemon=True)
    cli_thread.start()

     # TODO: find out how to place the window in a specific position -> didn't work with WSL2 on Windows 11
    #root.geometry('400x150+0+0')
    #wait for whichever comes first 
    root.mainloop()
    return decision['value']


if __name__ == "__main__":
    syscall_nr   = 123
    program_name = "example_program"
    program_hash = "abc123hash"

    decision = show_permission(syscall_nr, program_name, program_hash)
    print(f"User decision: {decision}")
