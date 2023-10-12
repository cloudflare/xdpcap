package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

type actionsFlag []xdpAction

func (a *actionsFlag) Set(val string) error {
	// Clear defaults
	*a = []xdpAction{}

	for _, action := range strings.Split(val, ",") {
		xdpAction, err := parseAction(action)
		if err != nil {
			return err
		}

		*a = append(*a, xdpAction)
	}

	return nil
}

func (a actionsFlag) String() string {
	strs := []string{}
	for _, action := range a {
		strs = append(strs, action.String())
	}

	return strings.Join(strs, ",")
}

type linkTypeFlag layers.LinkType

func (l *linkTypeFlag) Set(val string) error {
	val = strings.TrimSpace(strings.ToLower(val))

	for _, link := range linkTypes() {
		if val == strings.ToLower(link.String()) {
			*l = linkTypeFlag(link)
			return nil
		}
	}

	// Accept links we don't know about using their numeric value
	// Base 0 to allow for hex
	unknownLink, err := strconv.ParseInt(val, 0, 8)
	if err != nil {
		return errors.Errorf("unknown linktype %s", val)
	}

	*l = linkTypeFlag(unknownLink)
	return nil
}

func (l linkTypeFlag) String() string {
	return strings.ToLower(layers.LinkType(l).String())
}

// All valid LinkTypes
func linkTypes() []linkTypeFlag {
	links := []linkTypeFlag{}

	for link, meta := range layers.LinkTypeMetadata {
		if meta.Name == "UnknownLinkType" {
			continue
		}

		links = append(links, linkTypeFlag(link))
	}

	return links
}

var bpfRegex = regexp.MustCompile(`^\d+(?:,\d+ \d+ \d+ \d+)+,?$`)

func parseFilter(expr string, linkType layers.LinkType) ([]bpf.Instruction, error) {
	expr = strings.TrimSpace(expr)

	if bpfRegex.MatchString(expr) {
		return parsecBPF(expr)
	}

	return internal.TcpdumpExprToBPF(expr, linkType)
}

// parsecBPF parses a string of cBPF 4 tuple instructions, formatted as:
//
//	<length>,<opcode> <jt> <jf> <k>,...
func parsecBPF(bpfStr string) ([]bpf.Instruction, error) {
	cbpf := strings.Split(strings.TrimSuffix(bpfStr, ","), ",")

	if len(cbpf) < 1 {
		return nil, errors.Errorf("unable to split cBPF length & instructions")
	}

	insCount, err := strconv.Atoi(cbpf[0])
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse cBPF length")
	}

	insns := cbpf[1:]
	if len(insns) != insCount {
		return nil, errors.Errorf("declared cBPF instruction length %d doesn't match actual %d", insCount, len(insns))
	}

	cbpfInsns := make([]bpf.Instruction, len(insns))
	for i, insnStr := range insns {
		cbpfInsns[i], err = parseInstruction(insnStr)
		if err != nil {
			return nil, errors.Wrapf(err, "instruction %d", i)
		}
	}

	return cbpfInsns, nil
}

// parseInstruction parses a cBPF instruction, formatted as:
//
//	<opcode> <jt> <jf> <k>
func parseInstruction(insnStr string) (bpf.Instruction, error) {
	fields := strings.Split(insnStr, " ")
	if len(fields) != 4 {
		return nil, errors.Errorf("wrong number of fields, expected %d found %d", 4, len(fields))
	}

	op, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse OpCode")
	}

	jt, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse JumpTrue")
	}

	jf, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse JumpFalse")
	}

	k, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse K")
	}

	rawInsn := bpf.RawInstruction{
		Op: uint16(op),
		Jt: uint8(jt),
		Jf: uint8(jf),
		K:  uint32(k),
	}

	return rawInsn.Disassemble(), nil
}

type flags struct {
	*flag.FlagSet

	mapPath  string
	pcapFile *os.File

	quiet bool
	flush bool

	linkType layers.LinkType

	// Filter provided as input. Not in any particular format, for metadata / debugging only.
	filterExpr string
	filterOpts filterOpts

	maxPackets uint64
}

// parseFlags creates the flags, and attempts to parse args.
// On error, the returned flags is fully setup, but will not hold values for all the arguments.
func parseFlags(name string, args []string) (flags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	// flag insists on always printing things out in the case of errors, disable that
	fs.SetOutput(ioutil.Discard)

	flags := flags{
		FlagSet: fs,
	}

	flags.IntVar(&flags.filterOpts.perfPerCPUBuffer, "buffer", 8192, "Per CPU perf buffer size to create (`bytes`)")
	flags.IntVar(&flags.filterOpts.perfWatermark, "watermark", 1, "Perf watermark (`bytes`). Must be < buffer.")
	flags.Uint64Var(&flags.maxPackets, "c", 0, "Maximum number of packets to capture across all `actions`. 0 indicates unlimited")
	flags.BoolVar(&flags.quiet, "q", false, "Don't print statistics")
	flags.BoolVar(&flags.flush, "flush", false, "Flush pcap data written to <output> for every packet received")

	flags.filterOpts.actions = []xdpAction{}
	flags.Var((*actionsFlag)(&flags.filterOpts.actions), "actions", fmt.Sprintf("XDP `actions` to capture packets for. Comma separated list of names (%v) or enum values (default all actions exposed by the <debug map>)", xdpActions))

	flags.linkType = layers.LinkTypeEthernet
	flags.Var((*linkTypeFlag)(&flags.linkType), "linktype", fmt.Sprintf("Linktype to use when compiling <filter expr>. Name (%v) or enum value", linkTypes()))

	err := flags.Parse(args)
	if err != nil {
		return flags, err
	}

	if flags.NArg() < 2 {
		return flags, errors.New("missing required <debug map> / <output>")
	}

	flags.mapPath = flags.Arg(0)

	if output := flags.Arg(1); output == "-" {
		flags.pcapFile = os.Stdout
		flags.quiet = true
		flags.flush = true
	} else {
		var err error
		flags.pcapFile, err = os.Create(output)
		if err != nil {
			return flags, errors.Wrap(err, "creating output")
		}
	}

	// Default filter is match anything
	flags.filterExpr = strings.Join(flags.Args()[2:], " ")
	flags.filterOpts.filter, err = parseFilter(flags.filterExpr, flags.linkType)
	if err != nil {
		return flags, err
	}

	return flags, nil
}

func (flags flags) Usage() string {
	usage := strings.Builder{}

	usage.WriteString(fmt.Sprintf(
		`%s [options] <debug map> <output> [<filter expr>]

Capture packets from XDP programs matching a tcpdump / libpcap filter expression, <filter expr>.
<filter expr> can also be a classic BPF filter of the form '<op count>,<op> <jt> <jf> <k>,...'.

<output> may be "-" to write to stdout. Implies -q and -flush.

`, flags.Name()))

	// temporarily re-enable printing to get the default usage
	flags.SetOutput(&usage)
	flags.PrintDefaults()
	flags.SetOutput(ioutil.Discard)

	return usage.String()
}
