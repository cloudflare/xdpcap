#ifndef XDPCAP_HOOK_H
#define XDPCAP_HOOK_H

#include <linux/bpf.h>

/**
 * Create a bpf map suitable for use as an xdpcap hook point.
 *
 * For example:
 *   struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();
 */
#define XDPCAP_HOOK() { \
	.type = BPF_MAP_TYPE_PROG_ARRAY, \
	.key_size = sizeof(int), \
	.value_size = sizeof(int), \
	.max_entries = 5, \
}

/**
 * Return action, exposing the action and input packet to xdpcap hook.
 *
 *   return xdpcap_exit(ctx, &hook, XDP_PASS)
 *
 * is equivalent to:
 *
 *   return XDP_PASS;
 */
__attribute__((__always_inline__))
static inline enum xdp_action xdpcap_exit(struct xdp_md *ctx, struct bpf_map_def *hook, enum xdp_action action) {
	tail_call((void *)ctx, hook, action);
	return action;
}

#endif /* XDPCAP_HOOK_H */
