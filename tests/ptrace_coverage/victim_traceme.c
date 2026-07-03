// Protected target that attempts PTRACE_TRACEME against its parent.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

static void write_result(const char *path, const char *result) {
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", result);
        fclose(f);
    }
}

int main(int argc, char **argv) {
    const char *pidfile = argc >= 2 ? argv[1] : NULL;
    const char *resultfile = argc >= 3 ? argv[2] : NULL;

    if (pidfile) {
        FILE *f = fopen(pidfile, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());
            fclose(f);
        }
    }

    errno = 0;
    long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret == 0) {
        if (resultfile) write_result(resultfile, "TRACEME: ALLOWED");
        printf("TRACEME: ALLOWED\n");
    } else if (errno == EPERM || errno == EACCES) {
        if (resultfile) write_result(resultfile, "TRACEME: BLOCKED");
        printf("TRACEME: BLOCKED errno=%d\n", errno);
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "TRACEME: ERROR errno=%d %s", errno, strerror(errno));
        if (resultfile) write_result(resultfile, buf);
        printf("%s\n", buf);
    }

    fflush(stdout);
    for (;;) pause();
    return 0;
}
