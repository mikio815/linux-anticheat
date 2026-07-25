// Tries to access a given PID's memory via four vectors and classifies whether
// the permission check blocked it (EPERM/EACCES) or let it through (anything else).
// Running as root bypasses DAC so we observe only the LSM hook's effect.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

// Treat EPERM/EACCES as "blocked" and anything else (success/EFAULT/ESRCH/etc.) as "passed"
// Pre-padded to 20 visible chars so ANSI colors don't break alignment.
static const char *classify(int ok, int e) {
    if (ok) return "\033[1;32mALLOWED(success)    \033[0m";
    if (e == EPERM || e == EACCES) return "\033[1;31mBLOCKED             \033[0m";
    return "\033[1;32mALLOWED(passed-perm)\033[0m";
}

static void test_ptrace(pid_t pid) {
    errno = 0;
    long r = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    int e = errno;
    int ok = (r == 0);
    if (ok) {
        waitpid(pid, NULL, 0);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }
    printf("  PTRACE_ATTACH      : %s (errno=%d %s)\n",
           classify(ok, e), ok ? 0 : e, ok ? "" : strerror(e));
}

static void test_procmem(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", pid);
    errno = 0;
    int fd = open(path, O_RDWR);
    int e = errno;
    int ok = 0;
    if (fd >= 0) {
        char buf[8];
        errno = 0;
        ssize_t n = pread(fd, buf, sizeof buf, 0);
        e = errno;
        ok = (n >= 0);
        close(fd);
    }
    printf("  /proc/pid/mem      : %s (errno=%d %s)\n",
           classify(ok, e), ok ? 0 : e, ok ? "" : strerror(e));
}

static void test_pvw(pid_t pid) {
    char local[8] = "AAAAAAA";
    struct iovec liov = {local, sizeof local};
    struct iovec riov = {(void *)0x1000, sizeof local};
    errno = 0;
    ssize_t n = process_vm_writev(pid, &liov, 1, &riov, 1, 0);
    int e = errno;
    int ok = (n >= 0);
    printf("  process_vm_writev  : %s (errno=%d %s)\n",
           classify(ok, e), ok ? 0 : e, ok ? "" : strerror(e));
}

static void test_pvr(pid_t pid) {
    char local[8];
    struct iovec liov = {local, sizeof local};
    struct iovec riov = {(void *)0x1000, sizeof local};
    errno = 0;
    ssize_t n = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
    int e = errno;
    int ok = (n >= 0);
    printf("  process_vm_readv   : %s (errno=%d %s)\n",
           classify(ok, e), ok ? 0 : e, ok ? "" : strerror(e));
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <label> <pid>\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[2]);
    setvbuf(stdout, NULL, _IOLBF, 0); // interleave correctly with daemon banners
    printf("[%s] target pid=%d (attacker uid=%d)\n", argv[1], pid, getuid());
    test_ptrace(pid);
    usleep(600 * 1000); // pacing: let the daemon's block event land between vectors
    test_procmem(pid);
    usleep(600 * 1000);
    test_pvr(pid);
    usleep(600 * 1000);
    test_pvw(pid);
    return 0;
}
