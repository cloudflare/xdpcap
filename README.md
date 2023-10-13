# xdpcap

xdpcap is a tcpdump like tool for eXpress Data Path (XDP).
It can capture packets and actions / return codes from XDP programs,
using standard tcpdump / libpcap filter expressions.


## Instrumentation

XDP programs need to expose at least one hook point:

```C
struct bpf_map_def xdpcap_hook = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 4, // The max value of XDP_* constants
};
```

This map must be [pinned inside a bpffs](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs).

`hook.h` provides a convenience macro for declaring such maps:

```
#include "hook.h"

struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();
```

`return XDP_*` statements should be modified to "feed" a hook:

```C
#include "hook.h"

struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();

int xdp_main(struct xdp_md *ctx) {
	return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);
}
```

For a full example, see [testdata/xdp_hook.c](testdata/xdp_hook.c).

Depending on the granularity desired,
a program can expose multiple hook points,
or a hook can be reused across programs by using the same underlying map.

Package [xdpcap](https://godoc.org/github.com/cloudflare/xdpcap) provides a wrapper for
creating and pinning the hook maps using the [newtools/ebpf](https://godoc.org/github.com/cilium/ebpf) loader.

`xdpcap` supports attaching to XDP programs loaded with the
`BPF_F_XDP_HAS_FRAGS` flag (annotated with `xdp.frags`). It will attempt to
attach itself as usual to the XDP program and if that fails, it will retry
with the `BPF_F_XDP_HAS_FRAGS` flag.


## Installation

`go get -u github.com/cloudflare/xdpcap/cmd/xdpcap`


## Usage

* Capture packets to a pcap:
`xdpcap /path/to/pinned/map dump.pcap "tcp and port 80"`

* Display captured packets:
`sudo xdpcap /path/to/pinned/map - "tcp and port 80" | sudo tcpdump -r -`

if you wish to see the verifier logs in cases where the program fails the checks
you can use the `-print-verifier-logs` flag. You can control the size of the buffer
for the verifier logs using the flag `-verifier-log-size`.


## Limitations

* filters run after the instrumented XDP program.
If the program modifies the packet,
the filter should match the modified packet,
not the original input packet.

* capturing multi-buffer packets
`xdpcap` is currently unable to capture more than the first page of a packet.
If the instrumented XDP program is loaded with `BPF_F_XDP_HAS_FRAGS`, then
packets that span multiple physical pages won't be entirely captured.

## Tests

* `sudo -E $(which go) test`
