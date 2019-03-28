xdpcap
======

`xdpcap` is a way to instrument or debug your XDP code. Think of it as `tcpdump` for XDP.

To use it, you need to expose at least one hook point:

```C
struct bpf_map_def xdpcap_hook = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 4, // The max value of XDP_* constants
};
```

This map must be [pinned into a bpffs](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs) somewhere.

You can then feed packets packets to the hook like so:

```C
__attribute__((__always_inline__))
static inline enum xdp_action xdpcap_exit(struct xdp_md *ctx, enum xdp_action action) {
	tail_call((void *)ctx, &xdpcap_hook, action);
	return action;
}

int xdp_main(struct xdp_md *ctx) {
	return xdpcap_exit(ctx, XDP_PASS);
}
```

After installing `xdpcap` and `libpcap` you can dump packets by pointing `xdpcap` at the pinned map:

```
# go get github.com/cloudflare/xdpcap/cmd/xdpcap
# xdpcap /path/to/pinned/map dump.pcap "tcp and port 80"
```
