#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

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

void sys_rename(const char *oldpath, const char *newpath, const char *desc) {
    if (rename(oldpath, newpath) == -1) {
        printf("rename(%s) error: %m\n", desc);
    } else {
        printf("rename(%s) success\n", desc);
    }
}

void sys_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, const char *desc) {
    if (renameat(olddirfd, oldpath, newdirfd, newpath) == -1) {
        printf("renameat(%s) error: %m\n", desc);
    } else {
        printf("renameat(%s) success\n", desc);
    }
}

void sys_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags, const char *desc) {
    if (syscall(316, olddirfd, oldpath, newdirfd, newpath, flags) == -1) {
        printf("renameat2(%s) error: %m\n", desc);
    } else {
        printf("renameat2(%s) success\n", desc);
    }
}

void sys_link(const char *oldpath, const char *newpath, const char *desc) {
    if (link(oldpath, newpath) == -1) {
        printf("link(%s) error: %m\n", desc);
    } else {
        printf("link(%s) success\n", desc);
    }
}

void sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags, const char *desc) {
    if (linkat(olddirfd, oldpath, newdirfd, newpath, flags) == -1) {
        printf("linkat(%s) error: %m\n", desc);
    } else {
        printf("linkat(%s) success\n", desc);
    }
}

void sys_unlink(const char *pathname, const char *desc) {
    if (unlink(pathname) == -1) {
        printf("unlink(%s) error: %m\n", desc);
    } else {
        printf("unlink(%s) success\n", desc);
    }
}

void sys_unlinkat(int dirfd, const char *pathname, int flags, const char *desc) {
    if (unlinkat(dirfd, pathname, flags) == -1) {
        printf("unlinkat(%s) error: %m\n", desc);
    } else {
        printf("unlinkat(%s) success\n", desc);
    }
}

void sys_symlink(const char *target, const char *linkpath, const char *desc) {
    if (symlink(target, linkpath) == -1) {
        printf("symlink(%s) error: %m\n", desc);
    } else {
        printf("symlink(%s) success\n", desc);
    }
}

void sys_symlinkat(const char *target, int newdirfd, const char *linkpath, const char *desc) {
    if (symlinkat(target, newdirfd, linkpath) == -1) {
        printf("symlinkat(%s) error: %m\n", desc);
    } else {
        printf("symlinkat(%s) success\n", desc);
    }
}

void sys_mknod(const char *pathname, mode_t mode, dev_t dev, const char *desc) {
    if (mknod(pathname, mode, dev) == -1) {
        printf("mknod(%s) error: %m\n", desc);
    } else {
        printf("mknod(%s) success\n", desc);
    }
}

void sys_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev, const char *desc) {
    if (mknodat(dirfd, pathname, mode, dev) == -1) {
        printf("mknodat(%s) error: %m\n", desc);
    } else {
        printf("mknodat(%s) success\n", desc);
    }
}

void sys_mkdir(const char *pathname, mode_t mode, const char *desc) {
    if (mkdir(pathname, mode) == -1) {
        printf("mkdir(%s) error: %m\n", desc);
    } else {
        printf("mkdir(%s) success\n", desc);
    }
}

void sys_mkdirat(int dirfd, const char *pathname, mode_t mode, const char *desc) {
    if (mkdirat(dirfd, pathname, mode) == -1) {
        printf("mkdirat(%s) error: %m\n", desc);
    } else {
        printf("mkdirat(%s) success\n", desc);
    }
}

void sys_rmdir(const char *pathname, const char *desc) {
    if (rmdir(pathname) == -1) {
        printf("rmdir(%s) error: %m\n", desc);
    } else {
        printf("rmdir(%s) success\n", desc);
    }
}

int main() {
    
    // read
    sys_open("demo/normal-file.txt", O_RDONLY, 0, "O_RDONLY");
    sys_openat(AT_FDCWD, "demo/normal-file.txt", O_RDONLY, 0, "O_RDONLY");
    struct open_how how_read = {.flags = O_RDONLY};
    sys_openat2(AT_FDCWD, "demo/normal-file.txt", &how_read, sizeof(how_read), "O_RDONLY");

    // write
    sys_open("demo/normal-file.txt", O_WRONLY | O_TRUNC, 0, "O_WRONLY|O_TRUNC");
    sys_openat(AT_FDCWD, "demo/normal-file.txt", O_WRONLY | O_TRUNC, 0, "O_WRONLY|O_TRUNC");
    struct open_how how_write = {.flags = O_WRONLY | O_TRUNC};
    sys_openat2(AT_FDCWD, "demo/normal-file.txt", &how_write, sizeof(how_write), "O_WRONLY|O_TRUNC");

    // create
    sys_open("demo/new-normal-file.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR, "O_CREAT|O_WRONLY");
    unlink("demo/new-normal-file.txt");
    sys_creat("demo/new-normal-file.txt", S_IRUSR | S_IWUSR, "S_IRUSR | S_IWUSR");
    unlink("demo/new-normal-file.txt");
    sys_openat(AT_FDCWD, "demo/new-normal-file.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR, "O_CREAT|O_WRONLY");
    unlink("demo/new-normal-file.txt");
    struct open_how how_create = {.flags = O_CREAT | O_WRONLY,.mode = S_IRUSR | S_IWUSR};
    sys_openat2(AT_FDCWD, "demo/new-normal-file.txt", &how_create, sizeof(how_create), "O_CREAT|O_WRONLY");
    unlink("demo/new-normal-file.txt");

    // rename
    sys_rename("demo/normal-file.txt", "demo/normal-file-change.txt", "normal-file.txt->normal-file-change.txt");
    sys_renameat(AT_FDCWD, "demo/normal-file-change.txt", AT_FDCWD, "demo/normal-file-change2.txt", "normal-file-change.txt->normal-file-change2.txt");
    sys_renameat2(AT_FDCWD, "demo/normal-file-change2.txt", AT_FDCWD, "demo/normal-file.txt", 0, "normal-file-change2.txt->normal-file.txt");

    // link
    sys_link("demo/normal-file.txt", "demo/normal-file-link.txt", "normal-file.txt->normal-file-link.txt");
    sys_linkat(AT_FDCWD, "demo/normal-file.txt", AT_FDCWD, "demo/normal-file-linkat.txt", 0, "normal-file.txt->normal-file-linkat.txt");
    sys_unlink("demo/normal-file-link.txt", "normal-file-link.txt");
    sys_unlinkat(AT_FDCWD, "demo/normal-file-linkat.txt", 0, "normal-file-linkat.txt");
    sys_symlink("demo/normal-file.txt", "demo/normal-file-sym.txt", "normal-file.txt->normal-file-sym.txt");
    sys_symlinkat("demo/normal-file.txt", AT_FDCWD, "demo/normal-file-symat.txt", "normal-file.txt->normal-file-symat.txt");
    sys_unlink("demo/normal-file-sym.txt", "normal-file-sym.txt");
    sys_unlinkat(AT_FDCWD, "demo/normal-file-symat.txt", 0, "normal-file-symat.txt");

    // special file
    sys_mknod("demo/fifo", S_IFIFO | 0666, 0, "demo/fifo");
    sys_mknodat(AT_FDCWD, "demo/fifoat", S_IFIFO | 0666, 0, "demo/fifoat");
    sys_unlink("demo/fifo", "demo/fifo");
    sys_unlinkat(AT_FDCWD, "demo/fifoat", 0, "demo/fifoat");

    // directory
    sys_mkdir("demo/dir1", 0755, "demo/dir1");
    sys_mkdirat(AT_FDCWD, "demo/dir2", 0755, "demo/dir2");
    sys_rmdir("demo/dir1", "demo/dir1");
    sys_rmdir("demo/dir2", "demo/dir2");


    return 0;
}
