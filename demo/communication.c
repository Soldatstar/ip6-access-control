#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <sys/un.h>


void sys_pipe() {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        printf("pipe() error: %m\n");
    } else {
        printf("pipe() created: [%d, %d]\n", pipefd[0], pipefd[1]);
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

void sys_pipe2(int flag, const char* flag_name) {
    int pipefd[2];
    if (pipe2(pipefd, flag) == -1) {
        printf("pipe2(%s) error: %m\n", flag_name);
    } else {
        printf("pipe2(%s) created: [%d, %d]\n", flag_name, pipefd[0], pipefd[1]);
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

void sys_socket(int domain, int type, const char *desc) {
    int sock = socket(domain, type, 0);
    if (sock == -1) {
        printf("socket(%s) error: %m\n", desc);
    } else {
        printf("socket(%s) created\n", desc);
        close(sock);
    }
}

void sys_socketpair(int domain, int type, const char *desc) {
    int sv[2];
    if (socketpair(domain, type, 0, sv) == -1) {
        printf("socketpair(%s) error: %m\n", desc);
    } else {
        printf("socketpair(%s) created: [%d, %d]\n", desc, sv[0], sv[1]);
        close(sv[0]);
        close(sv[1]);
    }
}


int main() {
    sys_pipe();
    sys_pipe2(O_CLOEXEC, "O_CLOEXEC");
    sys_pipe2(O_NONBLOCK, "O_NONBLOCK");
    sys_pipe2(O_DIRECT, "O_DIRECT");
    
    sys_socket(AF_INET, SOCK_STREAM, "AF_INET, SOCK_STREAM");
    sys_socket(AF_INET, SOCK_DGRAM,  "AF_INET, SOCK_DGRAM");
    sys_socket(AF_UNIX, SOCK_STREAM, "AF_UNIX, SOCK_STREAM");
    sys_socket(AF_NETLINK, SOCK_RAW, "AF_NETLINK, SOCK_RAW");
    sys_socketpair(AF_UNIX, SOCK_STREAM, "AF_UNIX, SOCK_STREAM"); 

    return 0;
}
