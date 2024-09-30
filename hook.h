#ifndef XDPCAP_HOOK_H
#define XDPCAP_HOOK_H

#include <linux/bpf.h>

/**
 * If you are using libbpf >= 1.0.0 you need to define a map as follows:
 * struct {
 *   __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 *   __uint(max_entries, 5);
 *   __type(key, int);
 *   __type(value, int);
 * } xdpcap_hook __section(".maps");
 *
 * If you are using a libbpf version < 1.0.0 then you can define a map
 * like this:
 *   struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();
 *
 * In either case the map should then be passed to the xdpcap_exit function
 * to allow xdpcap to hook into the XDP entrypoint and dump the packets.
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
static inline enum xdp_action xdpcap_exit(struct xdp_md *ctx, void *hook_map, enum xdp_action action) {
	// tail_call
	// Some headers define tail_call (Cilium), others bpf_tail_call (kernel self tests). Use the helper ID directly
	((int (*)(struct xdp_md *, void *, int))12)(ctx, hook_map, action);
	return action;
}

#endif /* XDPCAP_HOOK_H */
