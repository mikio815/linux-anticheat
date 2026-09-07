/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ANTICHEAT_H
#define _ANTICHEAT_H

/*
 * Resolved once at init from a throwaway kprobe (see main.c), because
 * kallsyms_lookup_name() lost its module export in 5.7. Everything that needs
 * an unexported symbol goes through this.
 */
extern unsigned long (*kallsyms_lookup_name_fn)(const char *name);

int ebpf_guard_init(void);
void ebpf_guard_exit(void);

#endif /* _ANTICHEAT_H */
