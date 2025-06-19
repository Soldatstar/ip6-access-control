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
        if (ret == -1 && errno != 0) { \
            printf(#expr " = %ld, errno=%d (%s)\n", ret, errno, strerror(errno)); \
        } else { \
            printf(#expr " = %ld\n", ret); \
        } \
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
    if (fd == -1) {
        perror("open file_access.txt");
        return 1;
    }
    char buffer[100];
    for (int i = 0; i < 50; i++) {
        sprintf(buffer, "Writing line %d\n", i);
        CALL(write(fd, buffer, strlen(buffer)));
        CALL(lseek(fd, 0, SEEK_SET)); // Rewind for reading
        CALL(read(fd, (void *)malloc(10), 10));
        CALL(pread(fd, (void *)malloc(10), 10, 0));
    }


    // FileOpenCreate
    for (int i = 0; i < 20; i++) {
        char filename[50];
        sprintf(filename, "open_file_%d.txt", i);
        int temp_fd = open(filename, O_CREAT | O_WRONLY, 0644);
        if (temp_fd != -1) {
            CALL(write(temp_fd, "Hello", 5));
            close(temp_fd);
        } else {
            printf("open(%s) failed, errno=%d (%s)\n", filename, errno, strerror(errno));
        }
        sprintf(filename, "created_file_%d.txt", i);
        temp_fd = creat(filename, 0644);
         if (temp_fd != -1) {
            CALL(write(temp_fd, "World", 5));
            close(temp_fd);
        } else {
            printf("creat(%s) failed, errno=%d (%s)\n", filename, errno, strerror(errno));
        }
    }
    CALL(open("open_file.txt", O_CREAT | O_WRONLY, 0644));
    CALL(creat("created_file.txt", 0644));


    // FileSystemLinks
    for (int i = 0; i < 10; i++) {
        char hardlink_name[50], symlink_name[50], target_name[50];
        sprintf(target_name, "open_file_%d.txt", i % 20); // Link to existing files
        sprintf(hardlink_name, "hard_link_loop_%d.txt", i);
        sprintf(symlink_name, "sym_link_loop_%d.txt", i);

        CALL(link(target_name, hardlink_name));
        CALL(unlink(hardlink_name));
        CALL(symlink(target_name, symlink_name));
        CALL(unlinkat(AT_FDCWD, symlink_name, 0));
    }
    CALL(link("open_file.txt", "hard_link.txt"));
    CALL(unlink("hard_link.txt"));
    CALL(symlink("open_file.txt", "sym_link.txt"));
    CALL(unlinkat(AT_FDCWD, "sym_link.txt", 0));
    CALL(linkat(AT_FDCWD, "open_file.txt", AT_FDCWD, "hard_link2.txt", 0));
    CALL(symlinkat("open_file.txt", AT_FDCWD, "sym_link2.txt"));

    // FileSystemNodeManagement
    for (int i = 0; i < 15; i++) {
        char dirname[50], nodename[50];
        sprintf(dirname, "mydir_loop_%d", i);
        sprintf(nodename, "nodefile_loop_%d", i);
        CALL(mkdir(dirname, 0755));
        CALL(rmdir(dirname));
        CALL(mknod(nodename, S_IFREG | 0644, 0));
        CALL(unlink(nodename)); // Clean up nodefile
    }
    CALL(mkdir("mydir", 0755));
    CALL(rmdir("mydir"));
    CALL(mknod("nodefile", S_IFREG | 0644, 0));
    CALL(mkdirat(AT_FDCWD, "mydir2", 0755));
    CALL(mknodat(AT_FDCWD, "nodefile2", S_IFREG | 0644, 0));
    rmdir("mydir2");
    unlink("nodefile"); // Clean up original nodefile
    unlink("nodefile2"); // Clean up original nodefile2

    // FilePermissions
    for (int i = 0; i < 10; i++) {
        CALL(chmod("file_access.txt", (i % 2 == 0) ? 0600 : 0644));
        CALL(fchmod(fd, (i % 2 == 0) ? 0644 : 0600));
    }
    CALL(chmod("file_access.txt", 0600));
    CALL(fchmod(fd, 0600));
    CALL(chown("file_access.txt", getuid(), getgid()));
    CALL(fchown(fd, getuid(), getgid()));
    CALL(lchown("file_access.txt", getuid(), getgid()));
    CALL(umask(022));
    CALL(fchownat(AT_FDCWD, "file_access.txt", getuid(), getgid(), 0));
    CALL(fchmodat(AT_FDCWD, "file_access.txt", 0644, 0));

    // FileTimestamp
    for (int i = 0; i < 10; i++) {
        struct utimbuf times_loop;
        times_loop.actime = time(NULL) - (3600 + i*10);
        times_loop.modtime = time(NULL) - (1800 + i*10);
        CALL(utime("file_access.txt", &times_loop));
        struct timeval tv_loop[2] = {{time(NULL) - (1200 + i*10), 0}, {time(NULL) - (600 + i*10), 0}};
        CALL(utimes("file_access.txt", tv_loop));
    }
    struct utimbuf times;
    times.actime = time(NULL) - 3600;
    times.modtime = time(NULL) - 1800;
    CALL(utime("file_access.txt", &times));
    struct timeval tv[2] = {{time(NULL) - 1200, 0}, {time(NULL) - 600, 0}};
    CALL(utimes("file_access.txt", tv));
    struct timespec ts[2] = {{time(NULL) - 300, 0}, {time(NULL) - 100, 0}};
    CALL(utimensat(AT_FDCWD, "file_access.txt", ts, 0));

    // FileTruncation
    for (int i = 0; i < 10; i++) {
        CALL(truncate("file_access.txt", (i % 5) + 1));
        CALL(ftruncate(fd, (i % 3) + 1));
    }
    CALL(truncate("file_access.txt", 5));
    CALL(ftruncate(fd, 2));

    // FileExtendedAttributes
    const char *attr_base = "user.demo_attr_";
    char attr_name[50];
    const char *value = "demo_value";
    for (int i = 0; i < 10; i++) {
        sprintf(attr_name, "%s%d", attr_base, i);
        CALL(setxattr("file_access.txt", attr_name, value, strlen(value), 0));
        CALL(lsetxattr("file_access.txt", attr_name, value, strlen(value), 0)); // Will fail if symlink
        CALL(fsetxattr(fd, attr_name, value, strlen(value), 0));
        CALL(removexattr("file_access.txt", attr_name));
        // lremovexattr and fremovexattr might fail if previous removexattr succeeded
        errno = 0; lremovexattr("file_access.txt", attr_name); 
        if (errno != 0 && errno != ENODATA) printf("lremovexattr(%s) = -1, errno=%d (%s)\n", attr_name, errno, strerror(errno)); else printf("lremovexattr(%s) = 0\n", attr_name);
        errno = 0; fremovexattr(fd, attr_name);
        if (errno != 0 && errno != ENODATA) printf("fremovexattr(%s) = -1, errno=%d (%s)\n", attr_name, errno, strerror(errno)); else printf("fremovexattr(%s) = 0\n", attr_name);
    }
    const char *attr = "user.demo";
    const char *value_orig = "demo"; // Renamed variable
    CALL(setxattr("file_access.txt", attr, value_orig, strlen(value_orig), 0));
    CALL(lsetxattr("file_access.txt", attr, value_orig, strlen(value_orig), 0));
    CALL(fsetxattr(fd, attr, value_orig, strlen(value_orig), 0));
    CALL(removexattr("file_access.txt", attr));
    CALL(lremovexattr("file_access.txt", attr));
    CALL(fremovexattr(fd, attr));

    close(fd);
    // Clean up created files
    for (int i = 0; i < 20; i++) {
        char filename[50];
        sprintf(filename, "open_file_%d.txt", i);
        unlink(filename);
        sprintf(filename, "created_file_%d.txt", i);
        unlink(filename);
    }
    unlink("file_access.txt");
    unlink("open_file.txt");
    unlink("created_file.txt");
    // hard_link.txt and sym_link.txt already unlinked
    unlink("hard_link2.txt");
    unlink("sym_link2.txt");


    // Attempt to remove the temporary directory
    chdir(".."); // Move out of the directory before removing
    if (rmdir(dir) == -1) {
        perror("rmdir temp directory");
        // If rmdir fails, it might be because some files were not cleaned up.
        // For a demo, this might be acceptable, or you might want to list contents.
        printf("Failed to remove directory %s. It might not be empty.\n", dir);
    } else {
        printf("Successfully removed temp directory: %s\n", dir);
    }

    return 0;
}