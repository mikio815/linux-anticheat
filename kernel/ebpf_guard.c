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
#include <linux/rculist.h>
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

/*
 * The entry of each LSM shim is the first link in the chain that reaches our
 * programs, and it is the cheapest one to break: security_ptrace_access_check()
 * calls bpf_lsm_ptrace_access_check(), whose body is the "return 0" the
 * LSM_HOOK macro generates, and whose fentry site was patched into a jump to
 * the trampoline when the program attached. Writing the five-byte nop back is
 * exactly what detaching does, and it removes the hook completely -- while the
 * program stays in prog_idr, at the same address, hashing the same. Watching
 * the JIT image alone therefore misses the easiest attack there is.
 *
 * Nine bytes: endbr64 plus the five-byte patch site. That is the whole of what
 * decides whether the hook runs, and it stays inside the shim, so the window
 * can never spill into a neighbouring function whose own fentry site is being
 * patched for unrelated reasons.
 */
#define SHIM_WINDOW 9

struct shim_rec {
	const char *name;
	unsigned long addr;
	bool attached;
	u8 bytes[SHIM_WINDOW];
};

/*
 * Kept in step by hand with the #[lsm(hook = ...)] list in ebpf/src/lsm_*.rs. The
 * alternative was to walk trampoline_key_table and read tr->ip, which needs no
 * list -- but its size lives in kernel/bpf/trampoline.c rather than a header,
 * so it would have to be copied here as a bare 1024 and would silently start
 * missing trampolines if that ever changed. A name that goes stale is the
 * failure this module can actually notice and complain about; a table size that
 * goes stale is not.
 */
static struct shim_rec shims[] = {
	{ .name = "bpf_lsm_ptrace_access_check" },
	{ .name = "bpf_lsm_ptrace_traceme" },
	{ .name = "bpf_lsm_file_mprotect" },
	{ .name = "bpf_lsm_mmap_file" },
	{ .name = "bpf_lsm_bpf" },
	{ .name = "bpf_lsm_task_kill" },
};

/* An attached shim reaches its trampoline by a call or a jump; a detached one
 * is all nop. Used only to tell those two apart in a report -- the comparison
 * itself is a memcmp and decodes nothing. */
static bool has_branch(const u8 *p)
{
	unsigned int i;

	for (i = 0; i + 5 <= SHIM_WINDOW; i++)
		if (p[i] == 0xe8 || p[i] == 0xe9)
			return true;
	return false;
}

static void baseline_shims(void)
{
	unsigned int i, missing = 0, unattached = 0;

	for (i = 0; i < ARRAY_SIZE(shims); i++) {
		struct shim_rec *sh = &shims[i];

		sh->addr = kallsyms_lookup_name_fn(sh->name);
		if (!sh->addr) {
			missing++;
			pr_err("anticheat: %s not found\n", sh->name);
			continue;
		}

		memcpy(sh->bytes, (void *)sh->addr, SHIM_WINDOW);
		sh->attached = has_branch(sh->bytes);
		if (!sh->attached)
			unattached++;

		pr_info("anticheat: %-30s %px %*phN %s\n", sh->name,
			(void *)sh->addr, SHIM_WINDOW, sh->bytes,
			sh->attached ? "attached" : "NOT ATTACHED");
	}

	if (missing)
		pr_warn("anticheat: %u LSM shim(s) could not be resolved -- the name list is stale and those hooks are unguarded\n",
			missing);

	/*
	 * Baselining a hook that was never attached guards nothing: it records
	 * "detached" as the good state and stays quiet forever. The eBPF
	 * programs have to be loaded before this module.
	 */
	if (unattached)
		pr_warn("anticheat: %u LSM hook(s) were already unattached at baseline -- load the eBPF programs first or they are guarded as absent\n",
			unattached);
}

/* Reports unhooked and redirected separately: one is the hook being removed,
 * the other is it being pointed somewhere else. */
static unsigned int check_shims(void)
{
	unsigned int i, bad = 0;

	for (i = 0; i < ARRAY_SIZE(shims); i++) {
		struct shim_rec *sh = &shims[i];
		const u8 *now;

		if (!sh->addr)
			continue;

		now = (const u8 *)sh->addr;
		if (!memcmp(now, sh->bytes, SHIM_WINDOW))
			continue;

		bad++;
		pr_warn("anticheat: %s %s: %*phN -> %*phN\n", sh->name,
			sh->attached && !has_branch(now) ? "UNHOOKED" : "entry redirected",
			SHIM_WINDOW, sh->bytes, SHIM_WINDOW, now);
	}

	return bad;
}

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
	bool baselining;	/* first walk: there is nothing to check against yet */
};

/*
 * bpf_func and jited_len are read out of a struct that an attacker with kernel
 * write has already had the chance to edit, and they are then used as the base
 * and length of a read. Trusting them turns the guard into a way to crash the
 * machine instead of a way to report: point bpf_func just below an unmapped
 * page, or inflate jited_len, and the scan faults rather than saying anything.
 * So a range is read only when the baseline says it is the same range as
 * before. Anything else is reported by address and never dereferenced.
 *
 * A program that appeared after the baseline was taken therefore never gets
 * hashed. That is deliberate: it is not one of the programs being guarded, and
 * compare_with_baseline() ignores it anyway.
 */
static bool range_is_baselined(const struct prog_rec *r)
{
	unsigned int i;

	for (i = 0; i < baseline_count; i++)
		if (baseline[i].id == r->id)
			return baseline[i].func == r->func &&
			       baseline[i].jited_len == r->jited_len;
	return false;
}

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

	if (st->baselining || range_is_baselined(r)) {
		sha256((const u8 *)prog->bpf_func, prog->jited_len, r->hash);
		r->hashed = true;
	}

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
/*
 * Every piece of executable code BPF generates registers a bpf_ksym: the JIT
 * image of each program, but also each trampoline and each dispatcher. The list
 * is what /proc/kallsyms reads to produce its bpf_prog_* and bpf_trampoline_*
 * entries.
 *
 * Walking it is what closes the gap the program hashes leave open. An LSM
 * program is not reached through prog->bpf_func at all: the shim's fentry site
 * jumps to a trampoline, and the trampoline calls the program at an address
 * baked in when it was generated. That trampoline sits in the same
 * bpf_prog_pack memory as the programs, so rewriting the call inside it costs
 * an attacker exactly what rewriting a JIT image costs -- and hashing only the
 * programs left a way around that was no more expensive than the way through.
 *
 * The list also carries exact bounds, so nothing here has to work out how long
 * a trampoline is. start and end are the kernel's own bookkeeping.
 */
#define MAX_KSYMS 256
#define KSYM_SHORT 48

/*
 * A region is skipped rather than hashed if it claims to be bigger than this.
 * end is a field an attacker can write, and a scan that faults reports nothing.
 */
#define MAX_KSYM_LEN (1u << 20)

struct ksym_rec {
	unsigned long start;
	unsigned long end;
	char name[KSYM_SHORT];
	bool prog;
	bool hashed;
	u8 hash[SHA256_DIGEST_SIZE];
};

static struct list_head *bpf_kallsyms_ptr;

static struct ksym_rec ksyms[MAX_KSYMS];
static unsigned int ksym_count;

static struct ksym_rec ksym_baseline[MAX_KSYMS];
static unsigned int ksym_baseline_count;

/* Same rule as the program walk: a range is only read when the baseline says it
 * is the range it was. See range_is_baselined(). */
static bool ksym_range_is_baselined(const struct ksym_rec *r)
{
	unsigned int i;

	for (i = 0; i < ksym_baseline_count; i++)
		if (ksym_baseline[i].start == r->start)
			return ksym_baseline[i].end == r->end;
	return false;
}

/*
 * Programs are left to the prog_idr walk, which hashes the same bytes and can
 * name the program by id. Hashing them here too would cost a second pass over
 * every JIT image and report each tampering twice.
 *
 * The exception this creates: a program with subprograms registers a ksym per
 * subprogram, while the prog_idr walk hashes only bpf_func..+jited_len. None of
 * the anti-cheat's programs have subprograms, so nothing is uncovered today.
 */
static int walk_ksyms(bool baselining)
{
	struct bpf_ksym *ksym;
	unsigned int n = 0;

	if (!bpf_kallsyms_ptr)
		return -EINVAL;

	memset(ksyms, 0, sizeof(ksyms));

	rcu_read_lock();
	list_for_each_entry_rcu(ksym, bpf_kallsyms_ptr, lnode) {
		struct ksym_rec *r;
		unsigned long len;

		if (n >= MAX_KSYMS)
			break;

		r = &ksyms[n++];
		r->start = ksym->start;
		r->end = ksym->end;
		r->prog = ksym->prog;
		strscpy(r->name, ksym->name, sizeof(r->name));

		if (r->prog)
			continue;

		len = r->end - r->start;
		if (r->end <= r->start || len > MAX_KSYM_LEN)
			continue;

		if (baselining || ksym_range_is_baselined(r)) {
			sha256((const u8 *)r->start, len, r->hash);
			r->hashed = true;
		}
	}
	rcu_read_unlock();

	ksym_count = n;
	return 0;
}

static unsigned int compare_ksyms(void)
{
	unsigned int i, j, bad = 0;

	for (i = 0; i < ksym_baseline_count; i++) {
		struct ksym_rec *b = &ksym_baseline[i];
		struct ksym_rec *cur = NULL;

		if (b->prog)
			continue;

		for (j = 0; j < ksym_count; j++)
			if (ksyms[j].start == b->start) {
				cur = &ksyms[j];
				break;
			}

		if (!cur) {
			bad++;
			pr_warn("anticheat: %s (%px) is gone\n", b->name,
				(void *)b->start);
			continue;
		}

		if (cur->end != b->end) {
			bad++;
			pr_warn("anticheat: %s length %lu -> %lu\n", b->name,
				b->end - b->start, cur->end - cur->start);
		} else if (cur->hashed &&
			   memcmp(cur->hash, b->hash, SHA256_DIGEST_SIZE) != 0) {
			bad++;
			pr_warn("anticheat: %s CODE CHANGED\n", b->name);
		}
	}

	return bad;
}

static int baseline_ksyms(void)
{
	unsigned long addr = kallsyms_lookup_name_fn("bpf_kallsyms");
	unsigned int i, tramps = 0;
	int ret;

	if (!addr) {
		pr_err("anticheat: bpf_kallsyms not found -- trampolines are unguarded\n");
		return -ENOENT;
	}
	bpf_kallsyms_ptr = (struct list_head *)addr;

	ret = walk_ksyms(true);
	if (ret)
		return ret;

	for (i = 0; i < ksym_count; i++) {
		if (ksyms[i].prog)
			continue;
		tramps++;
		pr_info("anticheat: %-44s %px-%px %*phN\n", ksyms[i].name,
			(void *)ksyms[i].start, (void *)ksyms[i].end,
			8, ksyms[i].hash);
	}

	memcpy(ksym_baseline, ksyms, sizeof(ksym_baseline));
	ksym_baseline_count = ksym_count;

	pr_info("anticheat: %u BPF code regions, %u non-program (trampolines/dispatchers) baselined\n",
		ksym_count, tramps);
	return 0;
}

static void compare_with_baseline(s64 scan_us)
{
	unsigned int i, j;
	unsigned int changed = 0, moved = 0, gone = 0;
	unsigned int hooks = check_shims();
	unsigned int tramps;

	walk_ksyms(false);
	tramps = compare_ksyms();

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

		if (cur->jited_len != b->jited_len) {
			changed++;
			pr_warn("anticheat: prog id=%u (%s) jited_len %u -> %u\n",
				b->id, b->name, b->jited_len, cur->jited_len);
		} else if (cur->hashed &&
			   memcmp(cur->hash, b->hash, SHA256_DIGEST_SIZE) != 0) {
			changed++;
			pr_warn("anticheat: prog id=%u (%s) JIT CODE CHANGED\n",
				b->id, b->name);
		}
	}

	if (changed || moved || gone || hooks || tramps)
		pr_warn("anticheat: integrity scan: %u changed, %u moved, %u gone, %u hook entr%s, %u tramp (of %u baselined, %lldus)\n",
			changed, moved, gone, hooks, hooks == 1 ? "y" : "ies",
			tramps, baseline_count, scan_us);
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
	struct scan_state st = { .baselining = true };
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
	baseline_shims();
	baseline_ksyms();

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
