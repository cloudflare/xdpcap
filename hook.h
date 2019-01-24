#ifndef XDPCAP_HOOK_H
#define XDPCAP_HOOK_H

#include <linux/bpf.h>

__attribute__((section("maps"), used))
struct bpf_map_def xdpcap_hook = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 4, // Not using SET_BY_USERSPACE allows the map to be created without a xdpcap.Hook
};

__attribute__((__always_inline__))
static inline enum xdp_action xdpcap_exit(struct xdp_md *ctx, enum xdp_action action) {
	tail_call((void *)ctx, &xdpcap_hook, action);
	return action;
}

#endif /* XDPCAP_HOOK_H */
