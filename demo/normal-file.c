#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <utime.h>
#include <sys/xattr.h>

#define CALL(expr) \  
    do { \  
        errno = 0; \  
        long ret = (expr); \  
        printf(#expr " = %ld, errno=%d (%s)\n", ret, errno, strerror(errno)); \  
    } while (0)

int main() {
    char template[] = "/tmp/demoXXXXXX";
    char *dir = mkdtemp(template);
    if (!dir) {
        perror("mkdtemp");
        return 1;
    }
    printf("Using temp directory: %s\n", dir);
    chdir(dir);

    // FileAccess
    CALL(openat(AT_FDCWD, "file_access.txt", O_CREAT | O_RDWR, 0644));
    int fd = open("file_access.txt", O_RDWR);
    CALL(read(fd, (void *)malloc(10), 10));
    CALL(pread(fd, (void *)malloc(10), 10, 0));

    // FileOpenCreate
    CALL(open("open_file.txt", O_CREAT | O_WRONLY, 0644));
    CALL(creat("created_file.txt", 0644));

    // FileSystemLinks
    CALL(link("open_file.txt", "hard_link.txt"));
    CALL(unlink("hard_link.txt"));
    CALL(symlink("open_file.txt", "sym_link.txt"));
    CALL(unlinkat(AT_FDCWD, "sym_link.txt", 0));
    CALL(linkat(AT_FDCWD, "open_file.txt", AT_FDCWD, "hard_link2.txt", 0));
    CALL(symlinkat("open_file.txt", AT_FDCWD, "sym_link2.txt"));

    // FileSystemNodeManagement
    CALL(mkdir("mydir", 0755));
    CALL(rmdir("mydir"));
    CALL(mknod("nodefile", S_IFREG | 0644, 0));
    CALL(mkdirat(AT_FDCWD, "mydir2", 0755));
    CALL(mknodat(AT_FDCWD, "nodefile2", S_IFREG | 0644, 0));
    rmdir("mydir2");

    // FilePermissions
    CALL(chmod("file_access.txt", 0600));
    CALL(fchmod(fd, 0600));
    CALL(chown("file_access.txt", getuid(), getgid()));
    CALL(fchown(fd, getuid(), getgid()));
    CALL(lchown("file_access.txt", getuid(), getgid()));
    CALL(umask(022));
    CALL(fchownat(AT_FDCWD, "file_access.txt", getuid(), getgid(), 0));
    CALL(fchmodat(AT_FDCWD, "file_access.txt", 0644, 0));

    // FileTimestamp
    struct utimbuf times;
    times.actime = time(NULL) - 3600;
    times.modtime = time(NULL) - 1800;
    CALL(utime("file_access.txt", &times));
    struct timeval tv[2] = {{time(NULL) - 1200, 0}, {time(NULL) - 600, 0}};
    CALL(utimes("file_access.txt", tv));
    struct timespec ts[2] = {{time(NULL) - 300, 0}, {time(NULL) - 100, 0}};
    CALL(utimensat(AT_FDCWD, "file_access.txt", ts, 0));

    // FileTruncation
    CALL(truncate("file_access.txt", 5));
    CALL(ftruncate(fd, 2));

    // FileExtendedAttributes
    const char *attr = "user.demo";
    const char *value = "demo";
    CALL(setxattr("file_access.txt", attr, value, strlen(value), 0));
    CALL(lsetxattr("file_access.txt", attr, value, strlen(value), 0));
    CALL(fsetxattr(fd, attr, value, strlen(value), 0));
    CALL(removexattr("file_access.txt", attr));
    CALL(lremovexattr("file_access.txt", attr));
    CALL(fremovexattr(fd, attr));

    close(fd);
    return 0;
}