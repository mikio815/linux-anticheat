#!/usr/bin/env bash
# Injection-detection test: after launch the game does (1) an anonymous executable mmap
# and (2) a dlopen of a .so in /tmp, and we confirm the daemon's maps scanner reports
# both as INJECTION SUSPECT.
export PATH="$PATH:/usr/sbin"
HERE="$(cd "$(dirname "$0")" && pwd)"
DAEMON="$HERE/../../target/debug/anticheat"
PIDFILE=/tmp/ac_victim.pid
DLOG=/tmp/ac_daemon.log

# Stage a suspicious .so in /tmp (outside the whitelist)
cat > /tmp/evil.c <<'EOF'
__attribute__((constructor)) static void init(void) {}
EOF
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c || exit 1

# A victim that performs injection after startup
cat > /tmp/victim_inject.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
int main(int argc, char **argv) {
    if (argc >= 2) { FILE *f = fopen(argv[1], "w"); if (f) { fprintf(f, "%d\n", getpid()); fclose(f); } }
    printf("victim_inject pid=%d\n", getpid()); fflush(stdout);
    sleep(2); // inject after the baseline is recorded
    // (1) anonymous executable page (equivalent to reflective injection)
    void *p = mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) perror("mmap");
    // (2) dlopen a .so outside the whitelist
    void *h = dlopen("/tmp/evil.so", RTLD_NOW);
    if (!h) fprintf(stderr, "dlopen: %s\n", dlerror());
    printf("injected (anon=%p so=%p)\n", p, h); fflush(stdout);
    for (;;) pause();
}
EOF
# Put the game in a dedicated dir outside /tmp (so /tmp, which holds evil.so, isn't whitelisted)
sudo mkdir -p /opt/acgame
sudo gcc -O0 -o /opt/acgame/victim_inject /tmp/victim_inject.c -ldl || exit 1

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE" "$DLOG"
sleep 0.5

sudo "$DAEMON" /opt/acgame/victim_inject "$PIDFILE" >"$DLOG" 2>&1 &
for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
VICTIM="$(cat "$PIDFILE" 2>/dev/null)"
echo "victim pid=$VICTIM"

echo "=== wait for injection to occur (baseline 2s + inject + scan 5s) ==="
sleep 9

echo
echo "=== daemon log: baseline + INJECTION SUSPECT ==="
grep -E "maps baseline|INJECTION SUSPECT" "$DLOG"
echo "suspect count: $(grep -c 'INJECTION SUSPECT' "$DLOG")"

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE"
