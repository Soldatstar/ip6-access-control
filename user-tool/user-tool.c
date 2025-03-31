#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/user_tool.sock"

FILE *log_file;
//macro to log messages to console and log file (identical to supervisor)
void log_message(const char *format, ...) {
    va_list args;

    // Create a new format string with the suffix
    char new_format[256];
    snprintf(new_format, sizeof(new_format), "%s[User-Tool] ", format);

    // Print to console
    va_start(args, format);
    vprintf(new_format, args);
    va_end(args);

    // Print to log file
    if (log_file) {
        va_start(args, format);
        vfprintf(log_file, new_format, args);
        va_end(args);
        fflush(log_file);
    }
}

void handle_connection(int client_sock) {
    char buffer[256];
    ssize_t bytes_read;

    while ((bytes_read = read(client_sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        
        // Parse the syscall number and program hash
        int syscall_nr;
        char program_hash[65];
        if (sscanf(buffer, "SYSCALL:%d HASH:%64s", &syscall_nr, program_hash) != 2) {
            log_message("Invalid request format\n");
            continue;
        }

        // Convert syscall number to name (simplified for network calls)
        const char *syscall_name;
        switch (syscall_nr) {
            case 41:  // socket
                syscall_name = "socket";
                break;
            case 42:  // connect
                syscall_name = "connect";
                break;
            default:
                syscall_name = "unknown";
        }

        log_message("Program is attempting to make a system call: %s (%d)\n", 
                    syscall_name, syscall_nr);
        log_message("Allow this operation? (y/n): ");
        fflush(stdout);

        char response;
        scanf(" %c", &response);

        // Add a newline after the user input to separate it from the next log message
        printf("\n");

        const char *decision = (response == 'y' || response == 'Y') ? "ALLOW" : "DENY";
        write(client_sock, decision, strlen(decision));

        // Save decision to decision-[hash].log
        char log_filename[80];
        snprintf(log_filename, sizeof(log_filename), "decision-%s.log", program_hash);
        int fd = open(log_filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (fd != -1) {
            dprintf(fd, "System call: %s (%d) - Decision: %s\n", syscall_name, syscall_nr, decision);
            close(fd);
        } else {
            log_message("Failed to open decision log file: %s\n", strerror(errno));
        }
    }
}

int main() {
    log_file = fopen("user-tool.log", "a");

    int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1) {
        log_message("Socket creation failed: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Remove existing socket file if it exists
    unlink(SOCKET_PATH);

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_message("Failed to bind socket: %s\n", strerror(errno));
        return 1;
    }

    if (listen(server_sock, 5) == -1) {
        log_message("Failed to listen on socket: %s\n", strerror(errno));
        return 1;
    }
    log_message("User-tool daemon started. Listening on %s\n", SOCKET_PATH);
    log_message("Waiting for supervisor connection...\n");

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock == -1) {
            log_message("Failed to accept connection: %s\n", strerror(errno));
            continue;
        }

        log_message("Supervisor connected. Ready to handle requests.\n");
        handle_connection(client_sock);
        close(client_sock);
    }

    close(server_sock);
    unlink(SOCKET_PATH);
    fclose(log_file);
    return 0;
}
