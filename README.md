# xdpcap

xdpcap is a tcpdump like tool for eXpress Data Path (XDP).
It can capture packets and actions / return codes from XDP programs,
using standard tcpdump / libpcap filter expressions.


## Instrumentation

XDP programs need to expose at least one hook point. The hook point uses
a pinned map to copy packets to the userspace. Depending on the version
of libbpf you are using you will need to define the map in different ways.
In either case, the map must conform to the [ABI](https://github.com/cloudflare/xdpcap/blob/master/internal/abi.go).

### Libbpf >= 1.0.0

For versions of libbpf >= 1.0.0 a map should be defined simply as an anonymous
struct:

```C
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 4);
  __type(key, int);
  __type(value, int);
} xdpcap_hook SEC(".maps");
```

### Libbpf < 1.0.0

If you are using a libbpf version < 1.0.0 `hook.h` provides a convenience macro
for declaring such maps:

```
#include "hook.h"

struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();
```

### Using the map and the hook

This map must be [pinned inside a bpffs](https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html#bpffs).

`hook.h` also provides a simple function call that can you use to modidy all
statements like `return XDP_*`  to "feed" a hook:

```C
#include "hook.h"

/* xdpcap_hook map definition here */

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
