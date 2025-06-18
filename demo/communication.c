#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <mqueue.h>
#include <sys/shm.h>


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

void sys_msgget(const char *pathname, int proj_id, int msgflg, const char *desc) {
    key_t key = ftok(pathname, proj_id);
    if (key == -1) {
        printf("ftok(%s, %d) error: %m\n", pathname, proj_id);
        return;
    }

    int msgid = msgget(key, msgflg);
    if (msgid == -1) {
        printf("msgget(%s) error: %m\n", desc);
    } else {
        printf("msgget(%s) created: [%d]\n", desc, msgid);
        msgctl(msgid, IPC_RMID, NULL);
    }
}


void sys_mq_open(const char *name, int oflag, const char *desc) {
    mqd_t mqd = mq_open(name, oflag, 0666, NULL);
    if (mqd == (mqd_t)-1) {
        printf("mq_open(%s) error: %m\n", desc);
    } else {
        printf("mq_open(%s) created: [%d]\n", desc, (int)mqd);
        mq_close(mqd);
        mq_unlink(name);
    }
}

void sys_shmget(const char *pathname, int proj_id, int shmflg, size_t size, const char *desc) {
    key_t key = ftok(pathname, proj_id);
    if (key == -1) {
        printf("ftok(%s, %d) error: %m\n", pathname, proj_id);
        return;
    }

    int shmid = shmget(key, size, shmflg);
    if (shmid == -1) {
        printf("shmget(%s) error: %m\n", desc);
    } else {
        printf("shmget(%s) created: [%d]\n", desc, shmid);
        shmctl(shmid, IPC_RMID, NULL);
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
    
    sys_msgget("/tmp", 42, IPC_CREAT | 0666, "IPC_CREAT | 0666");
    sys_mq_open("/queue", O_CREAT | O_WRONLY, "O_CREAT | O_WRONLY");
    sys_mq_open("/queue", O_CREAT | O_RDONLY, "O_CREAT | O_RDONLY");
    sys_mq_open("/queue", O_CREAT | O_RDWR, "O_CREAT | O_RDWR");

    sys_shmget("/tmp", 65, IPC_CREAT | 0666, 1024, "IPC_CREAT | 0666");

    return 0;
}
