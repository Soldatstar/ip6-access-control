#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>


#define SOCKET_PATH "/tmp/user_tool.sock"

void handle_connection(int client_sock) {
    char buffer[256];
    ssize_t bytes_read;

    while ((bytes_read = read(client_sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        
        // Parse the syscall number and program hash
        int syscall_nr;
        char program_hash[65];
        if (sscanf(buffer, "SYSCALL:%d HASH:%64s", &syscall_nr, program_hash) != 2) {
            fprintf(stderr, "Invalid request format\n");
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

        printf("\nProgram is attempting to make a system call: %s (%d)\n", 
               syscall_name, syscall_nr);
        printf("Allow this operation? (y/n): ");
        fflush(stdout);

        char response;
        scanf(" %c", &response);

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
            perror("Failed to open decision log file");
        }
    }
}

int main() {
    int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Remove existing socket file if it exists
    unlink(SOCKET_PATH);

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }

    if (listen(server_sock, 5) == -1) {
        perror("listen");
        return 1;
    }

    printf("User-tool is running. Waiting for supervisor connection...\n");

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock == -1) {
            perror("accept");
            continue;
        }

        printf("Supervisor connected. Ready to handle requests.\n");
        handle_connection(client_sock);
        close(client_sock);
    }

    close(server_sock);
    unlink(SOCKET_PATH);
    return 0;
}
