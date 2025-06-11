        2 int open(const char *pathname, int flags, ... /* mode_t mode */ ); MODES: O_RDONLY, O_WRONLY, or O_RDWR FLAGS: O_APPEND        O_ASYNC O_CLOEXEC O_CREAT O_DIRECT O_DIRECTORY O_DSYNC O_EXCL O_LARGEFILE   O_NOATIME O_NOCTTY O_NOFOLLOW        O_NONBLOCK or O_NDELAY O_PATH O_SYNC O_TMPFILE O_TRUNC
         
        
        85 int creat(const char *pathname, mode_t mode);  creat()
       A call to creat() is equivalent to calling open() with flags equal
       to O_CREAT|O_WRONLY|O_TRUNC
        257 int openat(int dirfd, const char *pathname, int flags, ... /* mode_t mode */ );
        
        ## Manipulate filesystem (no file descriptor needed)

        ### filesystem state

        
        86 int link(const char *oldpath, const char *newpath);
        265 int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags); FLAGS: AT_EMPTY_PATH AT_SYMLINK_FOLLOW
        
        87 int unlink(const char *pathname);
        263 int unlinkat(int dirfd, const char *pathname, int flags); FLAG: AT_REMOVEDIR
        
        88 int symlink(const char *target, const char *linkpath);
        266 int symlinkat(const char *target, int newdirfd, const char *linkpath);

       133 mknod(const char *pathname, mode_t mode, dev_t dev);
       259 int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
       
       83 int mkdir(const char *pathname, mode_t mode);
       258 int mkdirat(int dirfd, const char *pathname, mode_t mode);
       
       84 int rmdir(const char *pathname);
       
       ## permission
       90 int chmod(const char *pathname, mode_t mode);
       91 int fchmod(int fd, mode_t mode); fd needed 
       268 int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); flags: AT_SYMLINK_NOFOLLOW
       
       
       92 int chown(const char *pathname, uid_t owner, gid_t group);
       93 int fchown(int fd, uid_t owner, gid_t group);
       94 int lchown(const char *pathname, uid_t owner, gid_t group);
       260 int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);  FLAGS: AT_EMPTY_PATH AT_SYMLINK_FOLLOW
       95 mode_t umask(mode_t mask);
    
       ## time
       132 int utime(const char *filename, const struct utimbuf *_Nullable times);
       235 int utimes(const char *filename, const struct timeval times[_Nullable 2]);
       280 int utimensat(int dirfd, const char *pathname, const struct timespec times[_Nullable 2], int flags); FLAGS: AT_EMPTY_PATH AT_SYMLINK_FOLLOW
       
       
       ## other
    
       76 int truncate(const char *path, off_t length);
       77 int ftruncate(int fd, off_t length);
       
       188 int setxattr(const char *path, const char *name, const void value[.size], size_t size, int flags); FLAGS:        XATTR_CREATE, XATTR_REPLACE
       189 int lsetxattr(const char *path, const char *name, const void value[.size], size_t size, int flags); FLAGS:        XATTR_CREATE, XATTR_REPLACE
       190 int fsetxattr(int fd, const char *name, const void value[.size], size_t size, int flags); FLAGS:        XATTR_CREATE, XATTR_REPLACE
       
       197 int removexattr(const char *path, const char *name);
       198 int lremovexattr(const char *path, const char *name);
       199 int fremovexattr(int fd, const char *name);
