#!/usr/bin/env bash
# 注入検出テスト: ゲームが起動後に (1)匿名実行ページ mmap (2)/tmp の .so dlopen を行い、
# daemon の maps スキャナが両方を INJECTION SUSPECT として報告することを確認する。
export PATH="$PATH:/usr/sbin"
HERE="$(cd "$(dirname "$0")" && pwd)"
DAEMON="$HERE/../../target/debug/anticheat"
PIDFILE=/tmp/ac_victim.pid
DLOG=/tmp/ac_daemon.log

# 怪しい .so を /tmp に用意 (ホワイトリスト外)
cat > /tmp/evil.c <<'EOF'
__attribute__((constructor)) static void init(void) {}
EOF
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c || exit 1

# 起動後に注入を行う victim
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
    sleep(2); // baseline 記録後に注入する
    // (1) 匿名実行ページ (reflective injection 相当)
    void *p = mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) perror("mmap");
    // (2) ホワイトリスト外の .so を dlopen
    void *h = dlopen("/tmp/evil.so", RTLD_NOW);
    if (!h) fprintf(stderr, "dlopen: %s\n", dlerror());
    printf("injected (anon=%p so=%p)\n", p, h); fflush(stdout);
    for (;;) pause();
}
EOF
# ゲームは /tmp 外の専用 dir に置く (evil.so のある /tmp をホワイトリストしないため)
sudo mkdir -p /opt/acgame
sudo gcc -O0 -o /opt/acgame/victim_inject /tmp/victim_inject.c -ldl || exit 1

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE" "$DLOG"
sleep 0.5

sudo "$DAEMON" /opt/acgame/victim_inject "$PIDFILE" >"$DLOG" 2>&1 &
for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
VICTIM="$(cat "$PIDFILE" 2>/dev/null)"
echo "victim pid=$VICTIM"

echo "=== 注入が起きるまで待機 (baseline 2s + inject + scan 5s) ==="
sleep 9

echo
echo "=== daemon log: baseline + INJECTION SUSPECT ==="
grep -E "maps baseline|INJECTION SUSPECT" "$DLOG"
echo "suspect count: $(grep -c 'INJECTION SUSPECT' "$DLOG")"

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE"
