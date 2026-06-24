// 指定 PID に対して 3 ベクトルでメモリアクセスを試み、
// 権限チェックで弾かれた (EPERM/EACCES) か通った (それ以外) かを分類する。
// root で実行することで DAC を素通りさせ、LSM フックの効果だけを観測する。
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

// EPERM/EACCES を「ブロック」、それ以外 (成功/EFAULT/ESRCH 等) を「通過」とみなす
static const char *classify(int ok, int e) {
    if (ok) return "ALLOWED(success)";
    if (e == EPERM || e == EACCES) return "BLOCKED";
    return "ALLOWED(passed-perm)";
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
    printf("  PTRACE_ATTACH      : %-20s (errno=%d %s)\n",
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
    printf("  /proc/pid/mem      : %-20s (errno=%d %s)\n",
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
    printf("  process_vm_writev  : %-20s (errno=%d %s)\n",
           classify(ok, e), ok ? 0 : e, ok ? "" : strerror(e));
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <label> <pid>\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[2]);
    printf("[%s] target pid=%d (attacker uid=%d)\n", argv[1], pid, getuid());
    test_ptrace(pid);
    test_procmem(pid);
    test_pvw(pid);
    return 0;
}
