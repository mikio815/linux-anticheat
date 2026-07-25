#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void write_pidfile(const char *path) {
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
}

static void write_result(const char *path, const char *result) {
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", result);
        fclose(f);
    }
}

static int is_perm_error(int err) {
    return err == EPERM || err == EACCES;
}

static int test_rwx_blocked(long page_size) {
    void *p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("FAIL mmap RW errno=%d %s\n", errno, strerror(errno));
        return 1;
    }

    errno = 0;
    int ret = mprotect(p, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    int err = errno;
    munmap(p, page_size);

    if (ret == -1 && is_perm_error(err)) {
        printf("PASS protected mprotect RWX blocked errno=%d %s\n", err, strerror(err));
        return 0;
    }

    if (ret == 0) {
        printf("FAIL protected mprotect RWX allowed\n");
        return 1;
    }

    printf("FAIL protected mprotect RWX errno=%d %s\n", err, strerror(err));
    return 1;
}

static int test_rwx_allowed(long page_size) {
    void *p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("FAIL mmap RW errno=%d %s\n", errno, strerror(errno));
        return 1;
    }

    errno = 0;
    int ret = mprotect(p, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    int err = errno;
    munmap(p, page_size);

    if (ret == 0) {
        printf("PASS control mprotect RWX allowed\n");
        return 0;
    }

    printf("FAIL control mprotect RWX errno=%d %s\n", err, strerror(err));
    return 1;
}

static int test_rx_allowed(long page_size, const char *label) {
    void *p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("FAIL %s mmap RW errno=%d %s\n", label, errno, strerror(errno));
        return 1;
    }

    errno = 0;
    int ret = mprotect(p, page_size, PROT_READ | PROT_EXEC);
    int err = errno;
    munmap(p, page_size);

    if (ret == 0) {
        printf("PASS %s mprotect RX allowed\n", label);
        return 0;
    }

    printf("FAIL %s mprotect RX errno=%d %s\n", label, err, strerror(err));
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <protected|control> <pidfile> <resultfile>\n", argv[0]);
        return 2;
    }

    int protected_mode = strcmp(argv[1], "protected") == 0;
    int control_mode = strcmp(argv[1], "control") == 0;
    if (!protected_mode && !control_mode) {
        fprintf(stderr, "invalid mode: %s\n", argv[1]);
        return 2;
    }

    write_pidfile(argv[2]);

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        printf("FAIL sysconf page size\n");
        write_result(argv[3], "RESULT: FAIL");
        return 1;
    }

    int failures = 0;
    failures += test_rx_allowed(page_size, argv[1]);
    failures += protected_mode ? test_rwx_blocked(page_size) : test_rwx_allowed(page_size);

    write_result(argv[3], failures ? "RESULT: FAIL" : "RESULT: PASS");
    return failures ? 1 : 0;
}
