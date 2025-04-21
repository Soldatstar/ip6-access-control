from sys import stderr, argv, exit
from os import execv, kill, getpid
from signal import SIGUSR1

from pyseccomp import SyscallFilter, ALLOW, TRAP

def init_seccomp():
    f = SyscallFilter(defaction=ALLOW)
    f.add_rule(TRAP, 'close')
    f.load()

def main():
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)
    
    init_seccomp()
    kill(getpid(),SIGUSR1)
    execv(argv[1],[argv[1]]+argv[2:])
    
if __name__ == "__main__":
    main()