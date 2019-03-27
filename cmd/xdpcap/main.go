package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
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
		perCPUBuffer = flag.Int("buffer", 8192, "Per CPU perf buffer size to create (bytes)")
		watermark    = flag.Int("watermark", 4096, "Perf watermark (bytes)")
	)

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, os.Args[0], "<debug map> <pcap> [<tcpdump filter expr>]")
		fmt.Fprintf(os.Stderr, "\nCapture packets handled by XDP (l4drop, Unimog) matching a tcpdump filter expression\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	mapFile := flag.Arg(0)
	pcapFile := flag.Arg(1)

	// Default filter is match anything
	expr := ""
	if flag.NArg() >= 3 {
		expr = strings.Join(flag.Args()[2:], " ")
	}

	err := capture(mapFile, pcapFile, expr, FilterOpts{
		PerfPerCPUBuffer: *perCPUBuffer,
		PerfWatermark:    *watermark,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func capture(mapPath string, pcapPath string, filterExpr string, opts FilterOpts) error {
	// BPF progs, maps and the perf buffer are stored in locked memory
	err := unlimitLockedMemory()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error setting locked memory limit:", err)
	}

	pcapFile, err := os.Create(pcapPath)
	if err != nil {
		return errors.Wrap(err, "openning pcap")
	}
	defer pcapFile.Close()

	// Exit gracefully
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	filter, err := NewFilter(mapPath, filterExpr, opts)
	if err != nil {
		return errors.Wrap(err, "creating filter")
	}

	// Need to close the filter after the pcap writer

	pcapWriter, interfaces, err := newPcapWriter(pcapFile, filterExpr, filter.Actions())
	if err != nil {
		filter.Close()
		return errors.Wrap(err, "writing pcap header")
	}
	defer pcapWriter.Flush()
	defer filter.Close()

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
			fmt.Print(str.String())
		}
	}()

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

	interfaces := make(map[XDPAction]int)

	// Seems to be the pcapgo way
	interfaces[actions[0]] = 0
	pcapWriter, err := pcapgo.NewNgWriterInterface(w, xdpInterface(actions[0], filterExpr), pcapgo.NgWriterOptions{})
	if err != nil {
		return nil, nil, err
	}

	if len(actions) == 1 {
		return pcapWriter, interfaces, nil
	}

	for _, action := range actions[1:] {
		id, err := pcapWriter.AddInterface(xdpInterface(action, filterExpr))
		if err != nil {
			return nil, nil, err
		}

		interfaces[action] = id
	}

	return pcapWriter, interfaces, nil
}

// xdpInterface creates a pcap interface from an xdp action
// This allows packets in a pcap to be associated with their original XDP Action
func xdpInterface(action XDPAction, expr string) pcapgo.NgInterface {
	return pcapgo.NgInterface{
		Name:     action.String(),
		Comment:  "XDP action",
		Filter:   expr,
		LinkType: layers.LinkTypeEthernet,
	}
}
