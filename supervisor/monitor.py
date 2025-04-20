from sys import stderr, argv, exit
from os import execv, kill, getpid
from signal import SIGUSR1

from pyseccomp import SyscallFilter, KILL, ALLOW

def seccomp(rule,syscall_name):
    f = SyscallFilter(defaction=ALLOW)
    
    if rule == "ALLOW":
        # f.add_rule(ALLOW, syscall_name)
        print(f"SECCOMP ALLOW {syscall_name}")
    
    if rule == "DENY":
        # f.add_rule(KILL, syscall_name)
        print(f"SECCOMP DENY {syscall_name}")
 
    # load the filter into the kernel
    f.load()

def main():
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)
    
    kill(getpid(),SIGUSR1)
    execv(argv[1],[argv[1]]+argv[2:])
    
if __name__ == "__main__":
    main()