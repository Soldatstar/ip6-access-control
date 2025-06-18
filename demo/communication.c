#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

void sys_pipe() {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        printf("pipe() error: %m\n");
    } else {
        printf("pipe(): read_fd = %d, write_fd = %d\n", pipefd[0], pipefd[1]);
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

void sys_pipe2(const char* flag_name, int flag) {
    int pipefd[2];
    if (pipe2(pipefd, flag) == -1) {
        printf("pipe2(%s) error: %m\n", flag_name);
    } else {
        printf("pipe2(%s): read_fd = %d, write_fd = %d\n", flag_name, pipefd[0], pipefd[1]);
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

int main() {
    sys_pipe();

    sys_pipe2("O_CLOEXEC", O_CLOEXEC);
    sys_pipe2("O_NONBLOCK", O_NONBLOCK);
    sys_pipe2("O_DIRECT", O_DIRECT);

    return 0;
}
