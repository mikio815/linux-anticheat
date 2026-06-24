// 保護対象プロセス役。PID を pidfile に書いて待機するだけ。
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc >= 2) {
        FILE *f = fopen(argv[1], "w");
        if (f) { fprintf(f, "%d\n", getpid()); fclose(f); }
    }
    printf("victim pid=%d\n", getpid());
    fflush(stdout);
    for (;;) pause();
    return 0;
}
