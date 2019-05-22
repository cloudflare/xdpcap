// Program xdpcap produces tcpdump compatible PCAPs from a BPF map.
//
// You can use it to introspect traffic dropped or redirected by XDP. It
// is also useful to examine any transformations done to a packet.
//
// xdpcap requires you to instrument your XDP code in a specific way,
// check the documentation at https://github.com/cloudflare/xdpcap
// for details.
//
// Once you have done so, you can capture into a file, or pipe
// straight into tcpdump:
//
//     xdpcap /path/to/pinned/map file.pcap
//     xdpcap /path/to/pinned/map - | tcpdump -r -
//
// xdpcap supports tcpdump / libpcap-style filter expressions.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

func main() {
	var (
		perCPUBuffer = flag.Int("buffer", 8192, "Per CPU perf buffer size to create (`bytes`)")
		watermark    = flag.Int("watermark", 4096, "Perf watermark (`bytes`)")
		quiet        = flag.Bool("q", false, "Don't print statistics")
		flush        = flag.Bool("flush", false, "Flush pcap data written to <output> for every packet received")
	)

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, os.Args[0], "<debug map> <output> [<tcpdump filter expr>]")
		fmt.Fprintf(os.Stderr, `
Capture packets from XDP programs matching a tcpdump filter expression.

<output> may be "-" to write to stdout. Implies -q and -flush.

`)
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	var pcapFile *os.File
	if output := flag.Arg(1); output == "-" {
		pcapFile = os.Stdout
		*quiet = true
		*flush = true
	} else {
		var err error
		pcapFile, err = os.Create(output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't create output:", err)
			os.Exit(1)
		}
	}
	defer pcapFile.Close()

	// Default filter is match anything
	expr := ""
	if flag.NArg() >= 3 {
		expr = strings.Join(flag.Args()[2:], " ")
	}

	mapFile := flag.Arg(0)
	err := capture(captureOpts{
		mapPath:    mapFile,
		pcapFile:   pcapFile,
		quiet:      *quiet,
		flush:      *flush,
		filterExpr: expr,
		filterOpts: FilterOpts{
			PerfPerCPUBuffer: *perCPUBuffer,
			PerfWatermark:    *watermark,
		},
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

type captureOpts struct {
	mapPath  string
	pcapFile *os.File

	quiet bool
	flush bool

	filterExpr string
	filterOpts FilterOpts
}

func capture(opts captureOpts) error {
	// BPF progs, maps and the perf buffer are stored in locked memory
	err := unlimitLockedMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error setting locked memory limit:", err)
	}

	// Exit gracefully
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	filter, err := NewFilter(opts.mapPath, opts.filterExpr, opts.filterOpts)
	if err != nil {
		return errors.Wrap(err, "creating filter")
	}

	// Need to close the filter after the pcap writer

	pcapWriter, interfaces, err := newPcapWriter(opts.pcapFile, opts.filterExpr, filter.Actions())
	if err != nil {
		filter.Close()
		return errors.Wrap(err, "writing pcap header")
	}
	defer pcapWriter.Flush()
	defer filter.Close()

	if !opts.quiet {
		// Print metrics every 1 second
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for range ticker.C {
				str := bytes.Buffer{}

				metrics, err := filter.Metrics()
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error getting metrics:", err)
					continue
				}

				for _, action := range filter.Actions() {
					fmt.Fprintf(&str, "%v: %d/%d\t", action, metrics[action].ReceivedPackets, metrics[action].MatchedPackets)
				}

				str.WriteString("(received/matched packets)\n")
				os.Stderr.WriteString(str.String())
			}
		}()
	}

	// Aggregate packets of all programs of the filter
	packets := make(chan Packet)
	errors := make(chan error)

	go filter.Forward(packets, errors)

	// Write out a pcap file from aggregated packets
	go func() {
		for {
			select {
			case pkt := <-packets:
				info := gopacket.CaptureInfo{
					Timestamp:      time.Now(),
					CaptureLength:  len(pkt.Data),
					Length:         len(pkt.Data),
					InterfaceIndex: interfaces[pkt.Action],
				}

				err := pcapWriter.WritePacket(info, pkt.Data)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error writing packet:", err)
				}

				if opts.flush {
					err = pcapWriter.Flush()
					if err != nil {
						fmt.Fprintln(os.Stderr, "Error flushing data:", err)
					}
				}

			case err := <-errors:
				fmt.Fprintln(os.Stderr, "Error receiving packet:", err)
			}
		}
	}()

	<-sigs
	return nil
}

// newPcapWriter creates a pcapWriter with an pcap interface (metadata) per xdp action
func newPcapWriter(w io.Writer, filterExpr string, actions []XDPAction) (*pcapgo.NgWriter, map[XDPAction]int, error) {
	if len(actions) == 0 {
		return nil, nil, errors.New("can't create pcap with no actions")
	}

	var interfaces []pcapgo.NgInterface
	actionIfcs := make(map[XDPAction]int)

	for id, action := range actions {
		interfaces = append(interfaces, pcapgo.NgInterface{
			Name:       action.String(),
			Comment:    "XDP action",
			Filter:     filterExpr,
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(math.MaxUint16),
		})
		actionIfcs[action] = id
	}

	pcapWriter, err := pcapgo.NewNgWriterInterface(w, interfaces[0], pcapgo.NgWriterOptions{})
	if err != nil {
		return nil, nil, err
	}

	for _, ifc := range interfaces[1:] {
		_, err := pcapWriter.AddInterface(ifc)
		if err != nil {
			return nil, nil, err
		}
	}

	// Flush the header out in case we're writing to stdout, this lets tcpdump print a reassuring message
	err = pcapWriter.Flush()
	if err != nil {
		return nil, nil, errors.Wrap(err, "writing pcap header")
	}

	return pcapWriter, actionIfcs, nil
}
