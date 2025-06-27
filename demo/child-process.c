#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        fprintf(stderr, "Create child error: %s\n", strerror(errno));
    } 
    else if (pid == 0) {
        // Kindprozess
        const char *filename = "demo/child-file.txt";
        int fd = open(filename, O_CREAT | O_WRONLY, 0644);

        if (fd < 0) {
            fprintf(stderr, "Create file in child process error: %s\n", strerror(errno));
        } else {
            printf("Create file in child process success: [%d]\n", fd);
            close(fd);
        }

        pid_t delete_pid = fork();
        if (delete_pid < 0) {
            fprintf(stderr, "Create delete child error: %s\n", strerror(errno));
        }
        else if (delete_pid == 0) {
            // Enkelprozess – führt das Löschen durch
            if (unlink(filename) != 0) {
                fprintf(stderr, "Delete file in grandchild process error: %s\n", strerror(errno));
            } else {
                printf("Delete file in grandchild process success\n");
            }
        } else {
            // Kindprozess wartet auf Enkel
            wait(NULL);
            printf("Done grandchild (delete) process execution\n");
        }
    } 
    else {
        // Elternprozess wartet auf Kind
        wait(NULL);
        printf("Done child process execution\n");
    }

    return 0;
}
