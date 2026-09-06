// SPDX-License-Identifier: GPL-2.0
/*
 * anticheat: thin kernel module.
 *
 * This first slice establishes symbol resolution only. Everything the module
 * is meant to do later -- DKOM audit, VDSO verification, physmap exclusion,
 * eBPF JIT integrity checks -- needs kernel symbols that are not exported to
 * modules, so none of it can be built until this works.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched/task.h>

static unsigned long (*kallsyms_lookup_name_fn)(const char *name);

/*
 * kallsyms_lookup_name() lost its export in 5.7, and so did
 * kallsyms_on_each_symbol(), so neither can be called directly. The function
 * itself is still a plain global with no NOKPROBE_SYMBOL, so registering a
 * throwaway kprobe on it hands back its address.
 */
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

/*
 * Symbols this module will need later. Resolving them here turns assumptions
 * in the design docs into facts about the kernel actually being targeted:
 * a rename upstream shows up as a resolution failure at load time rather than
 * as a mysterious NULL dereference once the feature using it is written.
 */
static struct {
	const char *name;
	const char *used_for;
	unsigned long addr;
} wanted[] = {
	{ "prog_idr",			 "eBPF integrity: walk BPF progs without bpf()" },
	{ "tsc_khz",			 "time source cross-check" },
	{ "set_direct_map_invalid_noflush", "physmap exclusion" },
	{ "set_direct_map_default_noflush", "physmap exclusion (restore)" },
};

static int resolve_kallsyms(void)
{
	unsigned long addr;

	addr = lookup_via_kprobe("kallsyms_lookup_name");
	if (!addr) {
		pr_err("anticheat: kprobe could not resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}

	kallsyms_lookup_name_fn = (unsigned long (*)(const char *))addr;
	return 0;
}

/*
 * init_task is one of the few symbols this module needs that is still
 * exported, which makes it the one case where the resolver can be checked
 * against ground truth instead of a plausibility test: if the resolver hands
 * back the same address the linker did, it works.
 */
static int verify_resolver(void)
{
	unsigned long resolved = kallsyms_lookup_name_fn("init_task");

	if (resolved != (unsigned long)&init_task) {
		pr_err("anticheat: resolver mismatch for init_task: kallsyms %px, linker %px\n",
		       (void *)resolved, &init_task);
		return -EINVAL;
	}

	pr_info("anticheat: symbol resolver verified against init_task\n");
	return 0;
}

static void probe_wanted_symbols(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(wanted); i++) {
		wanted[i].addr = kallsyms_lookup_name_fn(wanted[i].name);
		pr_info("anticheat: %-34s %s (%s)\n", wanted[i].name,
			wanted[i].addr ? "found" : "MISSING", wanted[i].used_for);
	}
}

static int __init anticheat_init(void)
{
	int ret;

	ret = resolve_kallsyms();
	if (ret)
		return ret;

	ret = verify_resolver();
	if (ret)
		return ret;

	probe_wanted_symbols();

	pr_info("anticheat: loaded\n");
	return 0;
}

static void __exit anticheat_exit(void)
{
	pr_info("anticheat: unloaded\n");
}

module_init(anticheat_init);
module_exit(anticheat_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux hybrid anti-cheat: thin kernel module");
