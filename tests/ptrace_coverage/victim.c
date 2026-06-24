// Plays the protected process. Just writes its PID to the pidfile and waits.
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
