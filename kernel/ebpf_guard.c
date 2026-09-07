// SPDX-License-Identifier: GPL-2.0
/*
 * eBPF guard: watches the anti-cheat's own BPF programs from outside eBPF,
 * because a BPF program cannot attest to its own integrity.
 *
 * Walking prog_idr directly (rather than going through
 * bpf(BPF_PROG_GET_NEXT_ID)) is the point: the syscall path is what an attacker
 * would tamper with, so the guard reads the kernel's own structure instead.
 */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

#include "anticheat.h"

static unsigned int scan_interval_sec = 5;
module_param(scan_interval_sec, uint, 0644);
MODULE_PARM_DESC(scan_interval_sec, "mean seconds between integrity scans (0 disables)");

/*
 * The interval is randomized around the mean rather than fixed. A fixed period
 * hands an attacker a predictable window: tamper, cheat, restore, all between
 * two scans, and nothing is ever seen. Windows' PatchGuard randomizes its own
 * check timing for the same reason.
 *
 * Returns a delay uniformly in [mean/2, 3*mean/2).
 */
static unsigned long next_scan_delay(void)
{
	unsigned int mean = scan_interval_sec;
	unsigned int half = mean / 2;
	unsigned int span = mean ? mean : 1;

	return secs_to_jiffies(half + get_random_u32_below(span));
}

static struct idr *prog_idr_ptr;

#define MAX_RECS 128

struct prog_rec {
	u32 id;
	u32 jited_len;
	unsigned long func;
	unsigned long vpage;	/* virtual page the JIT image starts in */
	char name[BPF_OBJ_NAME_LEN];
	u8 hash[SHA256_DIGEST_SIZE];
	bool hashed;
};

/*
 * Filled during the RCU walk. Static so the callback never allocates: it runs
 * under rcu_read_lock() and must not sleep.
 */
static struct prog_rec recs[MAX_RECS];
static unsigned int rec_count;

/* Baseline captured at init, compared against on every later scan. */
static struct prog_rec baseline[MAX_RECS];
static unsigned int baseline_count;

struct scan_state {
	unsigned int total;
	unsigned int jited;
	unsigned int recorded;
};

/*
 * The JIT image is hashed in place, under RCU. That is safe because
 * crypto/sha2.h's sha256() is documented "Context: Any context" -- it is the
 * lib/crypto implementation, not the crypto_shash API, so there is no tfm to
 * allocate and nothing that sleeps.
 *
 * Hashing here rather than copying the bytes out and hashing later matters:
 * the program must stay alive while its JIT image is read, and RCU is what
 * guarantees that.
 */
static int collect_prog(int id, void *p, void *data)
{
	struct bpf_prog *prog = p;
	struct scan_state *st = data;
	struct prog_rec *r;

	if (!prog)
		return 0;

	st->total++;
	if (!prog->jited || !prog->bpf_func || !prog->jited_len)
		return 0;
	st->jited++;

	if (st->recorded >= MAX_RECS)
		return 0;

	r = &recs[st->recorded++];
	r->id = prog->aux ? prog->aux->id : 0;
	r->jited_len = prog->jited_len;
	r->func = (unsigned long)prog->bpf_func;
	r->vpage = r->func >> PAGE_SHIFT;
	if (prog->aux)
		memcpy(r->name, prog->aux->name, sizeof(r->name));
	else
		strscpy(r->name, "?", sizeof(r->name));

	sha256((const u8 *)prog->bpf_func, prog->jited_len, r->hash);
	r->hashed = true;

	return 0;
}

static int walk_progs(struct scan_state *st)
{
	if (!prog_idr_ptr)
		return -EINVAL;

	memset(recs, 0, sizeof(recs));

	/*
	 * idr_for_each() may run concurrently with idr_alloc()/idr_remove() as
	 * long as the caller holds the RCU read lock, and bpf_prog teardown goes
	 * through call_rcu, so a program seen during the walk stays valid for it.
	 */
	rcu_read_lock();
	idr_for_each(prog_idr_ptr, collect_prog, st);
	rcu_read_unlock();

	rec_count = st->recorded;
	return 0;
}

/*
 * Report pages holding more than one JIT image. Since 5.18 the x86_64 JIT packs
 * programs into shared pages (bpf_prog_pack) and writes them through text_poke,
 * so a page generally does not belong to one program. That decides whether
 * per-program page protection -- physmap exclusion here, or page sealing from
 * the hypervisor later -- is possible at all.
 */
static void report_page_sharing(void)
{
	unsigned int i, j, shared_pages = 0;

	for (i = 0; i < rec_count; i++) {
		unsigned int on_page = 0;
		bool first = true;

		for (j = 0; j < i; j++)
			if (recs[j].vpage == recs[i].vpage) {
				first = false;
				break;
			}
		if (!first)
			continue;

		for (j = 0; j < rec_count; j++)
			if (recs[j].vpage == recs[i].vpage)
				on_page++;

		if (on_page < 2)
			continue;

		shared_pages++;
		pr_info("anticheat: page %lx holds %u JIT images:\n",
			recs[i].vpage, on_page);
		for (j = 0; j < rec_count; j++)
			if (recs[j].vpage == recs[i].vpage)
				pr_info("anticheat:   id=%-5u %-16s len=%u\n",
					recs[j].id, recs[j].name,
					recs[j].jited_len);
	}

	if (shared_pages)
		pr_warn("anticheat: %u page(s) shared between programs -- per-program page protection is not possible as-is\n",
			shared_pages);
}

/*
 * Compare the current scan against the baseline. Reports three distinct things,
 * because they mean different things to a server correlating the reports:
 * a changed hash is tampering, a moved bpf_func is a redirected program, and a
 * missing id is a program that went away.
 */
static void compare_with_baseline(s64 scan_us)
{
	unsigned int i, j;
	unsigned int changed = 0, moved = 0, gone = 0;

	for (i = 0; i < baseline_count; i++) {
		struct prog_rec *b = &baseline[i];
		struct prog_rec *cur = NULL;

		for (j = 0; j < rec_count; j++)
			if (recs[j].id == b->id) {
				cur = &recs[j];
				break;
			}

		if (!cur) {
			gone++;
			pr_warn("anticheat: prog id=%u (%s) is gone\n",
				b->id, b->name);
			continue;
		}

		if (cur->func != b->func) {
			moved++;
			pr_warn("anticheat: prog id=%u (%s) bpf_func moved %px -> %px\n",
				b->id, b->name, (void *)b->func,
				(void *)cur->func);
		}

		if (cur->jited_len != b->jited_len ||
		    memcmp(cur->hash, b->hash, SHA256_DIGEST_SIZE) != 0) {
			changed++;
			pr_warn("anticheat: prog id=%u (%s) JIT CODE CHANGED\n",
				b->id, b->name);
		}
	}

	if (changed || moved || gone)
		pr_warn("anticheat: integrity scan: %u changed, %u moved, %u gone (of %u baselined, %lldus)\n",
			changed, moved, gone, baseline_count, scan_us);
	else
		/* A clean scan every few seconds would drown dmesg, so only
		 * anomalies are logged at info level or above. */
		pr_debug("anticheat: integrity scan: %u programs unchanged (%lldus)\n",
			 baseline_count, scan_us);
}

static void scan_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(scan_work, scan_work_fn);

static void scan_work_fn(struct work_struct *work)
{
	struct scan_state st = {};
	ktime_t start = ktime_get();

	if (walk_progs(&st) == 0) {
		s64 us = ktime_us_delta(ktime_get(), start);

		compare_with_baseline(us);
	}

	if (scan_interval_sec)
		schedule_delayed_work(&scan_work, next_scan_delay());
}

void ebpf_guard_exit(void)
{
	/*
	 * Must cancel and wait: a work item still queued when the module text
	 * goes away is the classic way to make a module impossible to unload
	 * (or to panic on the next tick).
	 */
	cancel_delayed_work_sync(&scan_work);
}

int ebpf_guard_init(void)
{
	struct scan_state st = {};
	unsigned long addr;
	unsigned int i;
	int ret;

	addr = kallsyms_lookup_name_fn("prog_idr");
	if (!addr) {
		pr_err("anticheat: prog_idr not found\n");
		return -ENOENT;
	}
	prog_idr_ptr = (struct idr *)addr;

	ret = walk_progs(&st);
	if (ret)
		return ret;

	for (i = 0; i < rec_count; i++)
		pr_info("anticheat: prog id=%-5u %-16s len=%-6u func=%px page=%lx hash=%*phN\n",
			recs[i].id, recs[i].name, recs[i].jited_len,
			(void *)recs[i].func, recs[i].vpage,
			8, recs[i].hash);

	pr_info("anticheat: %u BPF programs, %u jited, %u baselined\n",
		st.total, st.jited, rec_count);

	report_page_sharing();

	memcpy(baseline, recs, sizeof(baseline));
	baseline_count = rec_count;

	if (scan_interval_sec) {
		pr_info("anticheat: integrity scan every ~%us (randomized %u-%us)\n",
			scan_interval_sec, scan_interval_sec / 2,
			scan_interval_sec / 2 + scan_interval_sec - 1);
		schedule_delayed_work(&scan_work, next_scan_delay());
	}

	return 0;
}
