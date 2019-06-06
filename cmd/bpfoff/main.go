// Program bpfoff converts a tcpdump / libpcap filter expression to a BPF filter matching packets with a fixed set of byte offsets.
// Useful for matching encapsulated packets.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s [options] <offsets> <tcpdump filter expr>

Convert <tcpdump filter expr> to a BPF filter matching packets with a fixed set of byte offsets, in the comma separated <offsets>.
<tcpdump filter expr> must be a layer 3 (IP) and up filter.
This allows encapsulated packets with fixed header sizes to be matched.
`, os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	offsets, err := parseOffsets(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing offsets:", err)
		os.Exit(1)
	}

	filterExpr := strings.Join(flag.Args()[1:], " ")

	filter, err := addOffsets(offsets, filterExpr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error converting filter:", err)
		os.Exit(1)
	}

	err = printFilter(filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Internal error:", err)
		os.Exit(1)
	}
}

func parseOffsets(offsets string) ([]uint32, error) {
	offs := []uint32{}

	for _, offsetStr := range strings.Split(offsets, ",") {
		off, err := strconv.ParseUint(offsetStr, 0, 32)
		if err != nil {
			return nil, err
		}

		offs = append(offs, uint32(off))
	}

	return offs, nil
}

// printFilter prints a filter in the standard / linux form to stdout
func printFilter(filter []bpf.Instruction) error {
	fmt.Printf("%d", len(filter))

	for _, insn := range filter {
		raw, err := insn.Assemble()
		if err != nil {
			return err
		}

		fmt.Printf(",%d %d %d %d", raw.Op, raw.Jt, raw.Jf, raw.K)
	}

	fmt.Printf("\n")
	return nil
}

func addOffsets(offsets []uint32, expr string) ([]bpf.Instruction, error) {
	// LinkTypeRaw == Packet begins directly with an IPv4 or IPv6 header
	// tcpdump defines:
	//  LINKTYPE_RAW = 101 (https://www.tcpdump.org/linktypes.html)
	//  DLT_RAW = 12 (https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h#L88)
	// layers.LinkTypeRaw uses 101, but it seems 12 is expected here
	filter, err := internal.TcpdumpExprToBPF(expr, layers.LinkType(12))
	if err != nil {
		return nil, err
	}

	return withOffsets(offsets, filter)
}

// withOffsets generates a new filter from filter, using a fixed set of offsets into the packet
func withOffsets(offsets []uint32, filter []bpf.Instruction) ([]bpf.Instruction, error) {
	// Final filter with all the offsets added
	newFilter := []bpf.Instruction{}

	// Sort the offsets so that the filter with the smallest offset is first
	// Ensures that the smallest offset can match even if the packet is shorted than the biggest offset
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	for _, offset := range offsets {
		offsetFilter, err := withOffset(offset, filter)
		if err != nil {
			return nil, err
		}

		newFilter = append(newFilter, offsetFilter...)
	}

	// No filters matched
	return append(newFilter, bpf.RetConstant{Val: 0}), nil
}

// withOffset rewrites filter to use a fixed offset into the packet
// new filter will return on match, fall through on no match
func withOffset(offset uint32, filter []bpf.Instruction) ([]bpf.Instruction, error) {
	newFilter := []bpf.Instruction{}

	// Appended to the end of newFilter to handle RetA
	// By only adding instructions between filters, we don't need to rewrite jump offsets as they're relative
	retATrailer := []bpf.Instruction{
		// No match, fall through to the next filter
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
		bpf.RetA{},
	}

	for pc, insn := range filter {
		// skip to go to the end of the filter, start of retATrailer
		skipEnd := uint32(len(filter) - pc - 1)

		switch i := insn.(type) {
		// All loads can just use a new offset into the packet
		case bpf.LoadAbsolute:
			newOff, err := addOffset(i.Off, uint32(offset))
			if err != nil {
				return nil, err
			}
			insn = bpf.LoadAbsolute{Off: newOff, Size: i.Size}
		case bpf.LoadMemShift:
			newOff, err := addOffset(i.Off, uint32(offset))
			if err != nil {
				return nil, err
			}
			insn = bpf.LoadMemShift{Off: newOff}
		case bpf.LoadIndirect:
			newOff, err := addOffset(i.Off, uint32(offset))
			if err != nil {
				return nil, err
			}
			insn = bpf.LoadIndirect{Off: newOff, Size: i.Size}

		case bpf.RetA:
			// Jump to retATrailer
			insn = bpf.Jump{Skip: skipEnd}

		case bpf.RetConstant:
			// No match, jump to next filter (after retATrailer)
			// We can keep matches, as we don't need to run any more filters
			if i.Val == 0 {
				insn = bpf.Jump{Skip: skipEnd + uint32(len(retATrailer))}
			}

		// Need magic to handle extensions such as length
		case bpf.LoadExtension, bpf.RawInstruction:
			return nil, errors.Errorf("BPF instruction %v unsupported", i)
		}

		newFilter = append(newFilter, insn)
	}

	return append(newFilter, retATrailer...), nil
}

// addOffset adds an offset, checking for overflow
func addOffset(loadOffset, addedOffset uint32) (uint32, error) {
	if math.MaxUint32-loadOffset < addedOffset {
		return 0, errors.Errorf("offset %d too large", addedOffset)
	}

	return loadOffset + addedOffset, nil
}
