from sys import stderr, argv, exit
from os import execv, kill, getpid
from signal import SIGUSR1

def main():
    
    if len(argv) != 2:
        print("Nutzung: %s program" % argv[0], file=stderr)
        exit(1)
    
    kill(getpid(),SIGUSR1)
    execv(argv[1],[argv[1]]+argv[2:])
    
if __name__ == "__main__":
    main()