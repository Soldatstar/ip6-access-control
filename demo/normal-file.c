#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#define _GNU_SOURCE
#include <stdlib.h>
#include <utime.h>
#include <sys/time.h>
#include <sys/xattr.h>
#include <time.h>


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

void sys_chmod(const char *pathname, mode_t mode, const char *desc) {
    if (chmod(pathname, mode) == -1) {
        printf("chmod(%s) error: %m\n", desc);
    } else {
        printf("chmod(%s) success\n", desc);
    }
}

void sys_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags, const char *desc) {
    if (fchmodat(dirfd, pathname, mode, flags) == -1) {
        printf("fchmodat(%s) error: %m\n", desc);
    } else {
        printf("fchmodat(%s) success\n", desc);
    }
}

void sys_chown(const char *pathname, uid_t owner, gid_t group, const char *desc) {
    if (chown(pathname, owner, group) == -1) {
        printf("chown(%s) error: %m\n", desc);
    } else {
        printf("chown(%s) success\n", desc);
    }
}

void sys_lchown(const char *pathname, uid_t owner, gid_t group, const char *desc) {
    if (lchown(pathname, owner, group) == -1) {
        printf("lchown(%s) error: %m\n", desc);
    } else {
        printf("lchown(%s) success\n", desc);
    }
}

void sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags, const char *desc) {
    if (fchownat(dirfd, pathname, owner, group, flags) == -1) {
        printf("fchownat(%s) error: %m\n", desc);
    } else {
        printf("fchownat(%s) success\n", desc);
    }
}

void sys_utime(const char *path, const struct utimbuf *times, const char *desc) {
    if (utime(path, times) == -1) {
        printf("utime(%s) error: %m\n", desc);
    } else {
        printf("utime(%s) success\n", desc);
    }
}

void sys_utimes(const char *path, const struct timeval times[2], const char *desc) {
    if (utimes(path, times) == -1) {
        printf("utimes(%s) error: %m\n", desc);
    } else {
        printf("utimes(%s) success\n", desc);
    }
}

void sys_utimensat(int dirfd, const char *file, const struct timespec times[2], const char *desc) {
    if (utimensat(dirfd, file, times, 0) == -1) {
        printf("utimensat(%s) error: %m\n", desc);
    } else {
        printf("utimensat(%s) success\n", desc);
    }
}


void sys_truncate(const char *path, const char *desc) {
    if (truncate(path, 100) == -1) {
        printf("truncate(%s) error: %m\n", desc);
    } else {
        printf("truncate(%s) success\n", desc);
    }
}

void sys_setxattr(const char *path, const char *name, const char *value, const char *desc) {
    if (setxattr(path, name, value, strlen(value), 0) == -1) {
        printf("setxattr(%s) error: %m\n", desc);
    } else {
        printf("setxattr(%s) success\n", desc);
    }
}

void sys_lsetxattr(const char *path, const char *name, const char *value, const char *desc) {
    if (lsetxattr(path, name, value, strlen(value), 0) == -1) {
        printf("lsetxattr(%s) error: %m\n", desc);
    } else {
        printf("lsetxattr(%s) success\n", desc);
    }
}

void sys_removexattr(const char *path, const char *name, const char *desc) {
    if (removexattr(path, name) == -1) {
        printf("removexattr(%s) error: %m\n", desc);
    } else {
        printf("removexattr(%s) success\n", desc);
    }
}

void sys_lremovexattr(const char *path, const char *name, const char *desc) {
    if (lremovexattr(path, name) == -1) {
        printf("lremovexattr(%s) error: %m\n", desc);
    } else {
        printf("lremovexattr(%s) success\n", desc);
    }
}


int main() {
    // init
    sys_creat("demo/normal-file.txt", S_IRUSR | S_IWUSR, "S_IRUSR | S_IWUSR");
    
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
    sys_unlink("demo/new-normal-file.txt", "demo/new-normal-file.txt");
    sys_openat(AT_FDCWD, "demo/new-normal-file.txt", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR, "O_CREAT|O_WRONLY");
    sys_unlink("demo/new-normal-file.txt", "demo/new-normal-file.txt");
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

    // permissions
    sys_chmod("demo/normal-file.txt", S_IROTH | S_IWOTH, "S_IRUSR | S_IWUSR");
    sys_fchmodat(AT_FDCWD, "demo/normal-file.txt", 0666, 0, "0755");

    // ownership
    sys_chown("demo/normal-file.txt", getuid(), getgid(),"getuid, getgid");
    sys_lchown("demo/normal-file.txt", getuid(), getgid(), "getuid, getgid");
    sys_fchownat(AT_FDCWD, "demo/normal-file.txt", getuid(), getgid(), 0, "getuid, getgid");

    //time
    struct utimbuf timess = {.actime = 1000000000,.modtime = 1000000000};
    sys_utime("demo/normal-file.txt", &timess, "demo/normal-file.txt");
    struct timeval times[2] = {{ .tv_sec = 1000000000, .tv_usec = 0 },{ .tv_sec = 1000000000, .tv_usec = 0 }};
    sys_utimes("demo/normal-file.txt", times, "demo/normal-file.txt");
    struct timespec timesss[2] = {{ .tv_sec = 1000000000, .tv_nsec = 0 },{ .tv_sec = 1000000000, .tv_nsec = 0 }};
    sys_utimensat(AT_FDCWD, "demo/normal-file.txt", timesss, "demo/normal-file.txt");

    //trunc
    sys_truncate("demo/normal-file.txt", "demo/normal-file.txt");

    //attributes
    sys_setxattr("demo/normal-file.txt", "user.demo", "demo", "user.demo:demo");
    sys_removexattr("demo/normal-file.txt", "user.demo", "user.demo");
    sys_lsetxattr("demo/normal-file.txt", "user.demo", "demo", "user.demo:demo");
    sys_lremovexattr("demo/normal-file.txt", "user.demo", "user.demo");

    //clean up
    sys_unlink("demo/normal-file.txt", "demo/normal-file.txt");

    return 0;
}
