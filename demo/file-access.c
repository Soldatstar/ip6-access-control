#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    const char *filename = "demo/file";
    int fd;
    char buffer[256];
    ssize_t bytes_read;
    pid_t child_pid;

    // Syscall open() im Lesemodus (O_RDONLY)
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("Fehler beim Öffnen der Datei.");
        return EXIT_FAILURE;
    }

    // Syscall read()
    // read() = 0 bedeutet dass das Ende der Datei erreicht wurde.
    // read() = -1 bedeutet dass dass ein Fehler beim Lesen aufgetreten ist.
    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        // printf("Gelesen: %s", buffer);
    }

    if (bytes_read == -1) {
        perror("Fehler beim Lesen der Datei (read)");
        close(fd);
        return EXIT_FAILURE;
    }

    // Syscall close()
    if (close(fd) == -1) {
        perror("Fehler beim Schliessen der Datei (close)");
        return EXIT_FAILURE;
    }

    // Childprozess starten
    child_pid = fork();

    if (child_pid == -1) {
        perror("Fehler beim Erstellen des Childprozesses (fork)");
        return EXIT_FAILURE;
    } 
    else if (child_pid == 0) {
        // Dies ist der Code, der im Childprozess ausgeführt wird
        sleep(2);
        exit(EXIT_SUCCESS);
    }
     
    return EXIT_SUCCESS;
}