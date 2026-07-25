#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static unsigned int parse_id(const char *s, const char *name) {
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!s[0] || (end && *end) || v > UINT32_MAX) {
        fprintf(stderr, "invalid %s id: %s\n", name, s);
        exit(2);
    }
    return (unsigned int)v;
}

static int get_fd_by_id(enum bpf_cmd cmd, unsigned int id) {
    union bpf_attr attr = {};

    switch (cmd) {
    case BPF_PROG_GET_FD_BY_ID:
        attr.prog_id = id;
        break;
    case BPF_MAP_GET_FD_BY_ID:
        attr.map_id = id;
        break;
    case BPF_LINK_GET_FD_BY_ID:
        attr.link_id = id;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    errno = 0;
    return bpf_sys(cmd, &attr);
}

static int is_perm_error(int err) {
    return err == EPERM || err == EACCES;
}

static int expect_blocked(enum bpf_cmd cmd, unsigned int id, const char *label) {
    int fd = get_fd_by_id(cmd, id);
    int err = errno;
    if (fd >= 0) {
        close(fd);
        printf("FAIL %-24s id=%u allowed fd=%d\n", label, id, fd);
        return 1;
    }
    if (is_perm_error(err)) {
        printf("PASS %-24s id=%u blocked errno=%d %s\n", label, id, err, strerror(err));
        return 0;
    }
    printf("FAIL %-24s id=%u errno=%d %s\n", label, id, err, strerror(err));
    return 1;
}

static int expect_missing_not_blocked(enum bpf_cmd cmd, const char *label) {
    const unsigned int missing_id = 0x7ffffffeU;
    int fd = get_fd_by_id(cmd, missing_id);
    int err = errno;
    if (fd >= 0) {
        close(fd);
        printf("FAIL %-24s unexpected fd=%d for missing id\n", label, fd);
        return 1;
    }
    if (is_perm_error(err)) {
        printf("FAIL %-24s missing id hit permission block errno=%d %s\n", label, err, strerror(err));
        return 1;
    }
    printf("PASS %-24s missing id not permission-blocked errno=%d %s\n", label, err, strerror(err));
    return 0;
}

static int expect_lsm_load_blocked(void) {
    static const char license[] = "GPL";
    union bpf_attr attr = {};

    attr.prog_type = BPF_PROG_TYPE_LSM;
    attr.insn_cnt = 0;
    attr.insns = 0;
    attr.license = (uint64_t)(uintptr_t)license;

    errno = 0;
    int fd = bpf_sys(BPF_PROG_LOAD, &attr);
    int err = errno;
    if (fd >= 0) {
        close(fd);
        printf("FAIL %-24s allowed fd=%d\n", "BPF_PROG_LOAD LSM", fd);
        return 1;
    }
    if (is_perm_error(err)) {
        printf("PASS %-24s blocked errno=%d %s\n", "BPF_PROG_LOAD LSM", err, strerror(err));
        return 0;
    }
    printf("FAIL %-24s errno=%d %s\n", "BPF_PROG_LOAD LSM", err, strerror(err));
    return 1;
}

static int expect_non_lsm_load_not_blocked(void) {
    static const char license[] = "GPL";
    union bpf_attr attr = {};

    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 0;
    attr.insns = 0;
    attr.license = (uint64_t)(uintptr_t)license;

    errno = 0;
    int fd = bpf_sys(BPF_PROG_LOAD, &attr);
    int err = errno;
    if (fd >= 0) {
        close(fd);
        printf("PASS %-24s allowed fd=%d\n", "BPF_PROG_LOAD non-LSM", fd);
        return 0;
    }
    if (is_perm_error(err)) {
        printf("FAIL %-24s permission-blocked errno=%d %s\n", "BPF_PROG_LOAD non-LSM", err, strerror(err));
        return 1;
    }
    printf("PASS %-24s not permission-blocked errno=%d %s\n", "BPF_PROG_LOAD non-LSM", err, strerror(err));
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <protected_prog_id> <protected_map_id> <protected_link_id>\n", argv[0]);
        return 2;
    }

    unsigned int prog_id = parse_id(argv[1], "prog");
    unsigned int map_id = parse_id(argv[2], "map");
    unsigned int link_id = parse_id(argv[3], "link");
    int failures = 0;

    failures += expect_blocked(BPF_PROG_GET_FD_BY_ID, prog_id, "BPF_PROG_GET_FD");
    failures += expect_blocked(BPF_MAP_GET_FD_BY_ID, map_id, "BPF_MAP_GET_FD");
    failures += expect_blocked(BPF_LINK_GET_FD_BY_ID, link_id, "BPF_LINK_GET_FD");

    failures += expect_missing_not_blocked(BPF_PROG_GET_FD_BY_ID, "BPF_PROG_MISSING");
    failures += expect_missing_not_blocked(BPF_MAP_GET_FD_BY_ID, "BPF_MAP_MISSING");
    failures += expect_missing_not_blocked(BPF_LINK_GET_FD_BY_ID, "BPF_LINK_MISSING");

    failures += expect_lsm_load_blocked();
    failures += expect_non_lsm_load_not_blocked();

    return failures ? 1 : 0;
}
