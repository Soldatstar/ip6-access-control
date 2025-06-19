#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <string.h>
#include <sys/stat.h>

void sys_open(const char *pathname, int flags, mode_t mode, const char *desc) {
    int fd = open(pathname, flags, mode);
    if (fd == -1) {
        printf("open(%s) error: %m\n", desc);
    } else {
        printf("open(%s) success\n", desc);
        close(fd);
    }
}

void sys_creat(const char *pathname, mode_t mode, const char *desc) {
    int fd = creat(pathname, mode);
    if (fd == -1) {
        printf("creat(%s) error: %m\n", desc);
    } else {
        printf("creat(%s) success\n", desc);
        close(fd);
    }
}

void sys_openat(int dirfd, const char *pathname, int flags, mode_t mode, const char *desc) {
    int fd = openat(dirfd, pathname, flags, mode);
    if (fd == -1) {
        printf("openat(%s) error: %m\n", desc);
    } else {
        printf("openat(%s) success\n", desc);
        close(fd);
    }
}

void sys_openat2(int dirfd, const char *pathname, struct open_how *how, size_t size, const char *desc) {
    int fd = syscall(SYS_openat2, dirfd, pathname, how, size);
    if (fd == -1) {
        printf("openat2(%s) error: %m\n", desc);
    } else {
        printf("openat2(%s) success\n", desc);
        close(fd);
    }
}

int main() {
    
    // Lesen
    sys_open("demo/normal-file.txt", O_RDONLY, 0, "O_RDONLY");
    sys_openat(AT_FDCWD, "demo/normal-file.txt", O_RDONLY, 0, "O_RDONLY");
    struct open_how how_read = {.flags = O_RDONLY};
    sys_openat2(AT_FDCWD, "demo/normal-file.txt", &how_read, sizeof(how_read), "O_RDONLY");

    // Schreiben
    sys_open("demo/normal-file.txt", O_WRONLY | O_TRUNC, 0, "O_WRONLY|O_TRUNC");
    sys_openat(AT_FDCWD, "demo/normal-file.txt", O_WRONLY | O_TRUNC, 0, "O_WRONLY|O_TRUNC");
    struct open_how how_write = {.flags = O_WRONLY | O_TRUNC};
    sys_openat2(AT_FDCWD, "demo/normal-file.txt", &how_write, sizeof(how_write), "O_WRONLY|O_TRUNC");

    // Erstellen
    mode_t mode = S_IRUSR | S_IWUSR;
    sys_open("demo/new-normal-file.txt", O_CREAT | O_WRONLY, mode, "O_CREAT|O_WRONLY");
    unlink("demo/new-normal-file.txt");
    sys_creat("demo/new-normal-file.txt", mode, "S_IRUSR | S_IWUSR");
    unlink("demo/new-normal-file.txt");
    sys_openat(AT_FDCWD, "demo/new-normal-file.txt", O_CREAT | O_WRONLY, mode, "O_CREAT|O_WRONLY");
    unlink("demo/new-normal-file.txt");
    struct open_how how_create = {.flags = O_CREAT | O_WRONLY,.mode = mode};
    sys_openat2(AT_FDCWD, "demo/new-normal-file.txt", &how_create, sizeof(how_create), "O_CREAT|O_WRONLY");
    unlink("demo/new-normal-file.txt");

    return 0;
}
