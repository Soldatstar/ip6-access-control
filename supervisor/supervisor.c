#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/un.h>
#include <linux/unistd.h>

#define USER_TOOL_SOCKET "/tmp/user_tool.sock"

char program_hash[65]; //Global variable to store the hash of the executing program

FILE *log_file;
//macro to log messages to console and log file
void log_message(const char *format, ...) {
    va_list args;

    // Create a new format string with the suffix
    char new_format[256];
    snprintf(new_format, sizeof(new_format), "%s [Supervisor] ", format);

    // Print to console
    va_start(args, format);
    vprintf(new_format, args);
    va_end(args);

    // Print to log file
    if (log_file) {
        va_start(args, format);
        vfprintf(log_file, new_format, args);
        va_end(args);
    }
}

// Helper function to get syscall name
const char* get_syscall_name(long syscall_nr) {
    switch(syscall_nr) {
        case SYS_socket:
            return "socket";
        case SYS_connect:
            return "connect";
        default:
            return "unknown";
    }
}


// Function to compute SHA-256 hash of a string
void compute_sha256(const char *str, char outputBuffer[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = '\0';
}

// #####Function to check if decision exists in the log file#####
int check_decision_log(const char *syscall_name, long syscall_nr) {
    char log_filename[128];
    snprintf(log_filename, sizeof(log_filename), "../user-tool/decision-%s.log", program_hash);
    
    log_message("Opening policy file: %s\n", log_filename);
    FILE *file = fopen(log_filename, "r");
    if (!file) {
        log_message("Failed to open decision log file\n");
        return 0;
    }

    char line[256];
    char syscall_nr_str[20];
    sprintf(syscall_nr_str, "%ld", syscall_nr);
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, syscall_name) && strstr(line, syscall_nr_str)) {
            if (strstr(line, "ALLOW")) {
                fclose(file);
                return 1; // Decision: ALLOW
            } else if (strstr(line, "DENY")) {
                fclose(file);
                return -1; // Decision: DENY
            }
        }
        
    }

    fclose(file);
    return 0; // Decision not found
}

// Function to connect to user-tool
int connect_to_user_tool() {
    log_message("Connecting to user-tool daemon...\n");
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("[Supervisor] Failed to create socket for user-tool connection");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, USER_TOOL_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("[Supervisor] Failed to connect to user-tool");
        close(sock);
        return -1;
    }
    log_message("Successfully connected to user-tool daemon\n");
    return sock;
}

// Function to ask user-tool for permission
int ask_permission(int user_tool_sock, int syscall_nr) {
    char buffer[256];
    
    log_message("Requesting permission for syscall %s (%d)\n", 
                get_syscall_name(syscall_nr), syscall_nr);
    // Send the syscall number and hash to the user tool
    snprintf(buffer, sizeof(buffer), "SYSCALL:%ld HASH:%s", syscall_nr, program_hash);
    if (write(user_tool_sock, buffer, strlen(buffer)) == -1) {
        perror("write");
        return 0;
    }

    char response[8];
    ssize_t bytes = read(user_tool_sock, response, sizeof(response) - 1);
    if (bytes <= 0) {
        perror("[Supervisor] Failed to read response from user-tool");
        return -1;
    }
    response[bytes] = '\0';
    log_message("User-tool response: %s\n", response);

    return strcmp(response, "ALLOW") == 0;
}

int main(int argc, char *argv[]) {
    log_file = fopen("supervisor.log", "a");
    if (!log_file) {
        log_message("Failed to open log file\n");
        return 1;
    }

    if (argc < 2) {
        log_message("Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }


    log_message("Starting supervision of program: %s\n", argv[1]);
    // Build absolute path for target program
    char abs_path[1024];
    if (argv[1][0] != '/') {
        if (realpath(argv[1], abs_path) == NULL) {
            perror("[Supervisor] Failed to resolve program path");
            return 1;
        }
        argv[1] = abs_path;
    }
    log_message("Full program path: %s\n", argv[1]);
    compute_sha256(argv[1], program_hash);
    log_message("Program hash: %s\n", program_hash);

    int user_tool_sock = connect_to_user_tool();
    if (user_tool_sock == -1) {
        log_message("ERROR: Make sure user-tool is running first!\n");
        return 1;
    }

    pid_t child = fork();
    if (child == -1) {
        log_message("Fork failed\n");
        return 1;
    }

    if (child == 0) {
        // Child process - this will become the monitored program
        log_message("Starting monitored program (PID: %d)\n", getpid());
        
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            log_message("Failed to set up ptrace\n");
            exit(1);
        }

        // Stop to let parent set up monitoring
        raise(SIGSTOP);

        // Set up seccomp
        log_message("Setting up  system call filtering...\n");
        prctl(PR_SET_NO_NEW_PRIVS, 1);
        
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
                     (offsetof(struct seccomp_data, nr))),
            
            // Check for socket syscall
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
            
            // Check for connect syscall
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
            
            // Allow all other syscalls
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
        };

        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
            log_message("Failed to set up seccomp filter\n");
            exit(1);
        }

        log_message("Executing monitored program: %s\n", argv[1]);
        execv(argv[1], &argv[1]);
        log_message("Failed to execute program\n");
        exit(1);
    }

    // Parent process - this is the supervisor
    log_message("Monitoring process PID: %d\n", child);
    
    // Wait for child to stop
    int status;
    if (waitpid(child, &status, 0) == -1) {
        log_message("Initial waitpid failed\n");
        return 1;
    }

    // Set up tracing options
    if (ptrace(PTRACE_SETOPTIONS, child, 0, 
               PTRACE_O_TRACESYSGOOD | 
               PTRACE_O_TRACESECCOMP) == -1) {
        log_message("Failed to set ptrace options\n");
        return 1;
    }

    // Continue the child
    ptrace(PTRACE_CONT, child, 0, 0);

    log_message("Beginning system call monitoring...\n");

    while (1) {
        if (waitpid(child, &status, 0) == -1) {
            log_message("waitpid failed\n");
            break;
        }

        if (WIFEXITED(status)) {
            log_message("Monitored program exited with status %d\n", 
                        WEXITSTATUS(status));
            break;
        }

        if (WIFSTOPPED(status)) {
            int stopsig = WSTOPSIG(status);
            if (stopsig == (SIGTRAP | 0x80) || 
                (stopsig == SIGTRAP && status >> 8 == (SIGTRAP | PTRACE_EVENT_SECCOMP << 8))) {
                
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) == -1) {
                    log_message("Failed to get registers\n");
                    continue;
                }

                #ifdef __x86_64__
                long syscall = regs.orig_rax;
                #else
                long syscall = regs.orig_eax;
                #endif

                if (syscall == SYS_socket || syscall == SYS_connect) {
                    const char *syscall_name = get_syscall_name(syscall);
                    log_message("Intercepted %s system call\n", syscall_name);
                    int decision = check_decision_log(syscall_name, syscall);
                    if (decision == 1) {
                        log_message("Allowing %s system call based on policy\n", syscall_name);
                    } else if (decision == -1) {
                        log_message("Blocking %s system call based on policy\n", syscall_name);
                        #ifdef __x86_64__
                        regs.rax = -EPERM;
                        #else
                        regs.eax = -EPERM;
                        #endif
                        if (ptrace(PTRACE_SETREGS, child, 0, &regs) == -1) {
                            log_message("Failed to set registers\n");
                        }
                    } else {
                        int allow = ask_permission(user_tool_sock, syscall);
                        if (!allow) {
                            log_message("Blocking %s system call based on user decision\n", syscall_name);
                            #ifdef __x86_64__
                            regs.rax = -EPERM;
                            #else
                            regs.eax = -EPERM;
                            #endif
                            if (ptrace(PTRACE_SETREGS, child, 0, &regs) == -1) {
                                log_message("Failed to set registers\n");
                            }
                        } else {
                            log_message("Allowing %s system call based on user decision\n", syscall_name);
                        }
                    }
                }
            }
            ptrace(PTRACE_SYSCALL, child, 0, 0);
        }
    }

    close(user_tool_sock);
    fclose(log_file);
    return 0;
}
