package main

import (
	"flag"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func TestRequiredArgs(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{})
	if err == nil {
		t.Fatal("missing main args")
	}

	flags, err = parseFlags("", []string{"foo"})
	if err == nil {
		t.Fatal("missing main args")
	}

	// Two args - empty filter
	flags, err = parseFlags("", []string{"foo", output})
	if err != nil {
		t.Fatal(err)
	}
	requireFlags(t, output, defaultFlags("foo"), flags)
}

func TestOutputInvalid(t *testing.T) {
	_, err := parseFlags("", []string{"foo", "/"})
	if err == nil {
		t.Fatal("impossible output file created")
	}
}

func TestOutputStdout(t *testing.T) {
	flags, err := parseFlags("", []string{"foo", "-"})
	if err != nil {
		t.Fatal(err)
	}

	if flags.pcapFile != os.Stdout {
		t.Fatal("output not stdout")
	}

	if flags.quiet != true {
		t.Fatal("stdout should set quiet")
	}

	if flags.flush != true {
		t.Fatal("stdout should set flush")
	}
}

func TestFilterLibpcap(t *testing.T) {
	output := tempOutput(t)

	// Single arg
	flags, err := parseFlags("", []string{"foo", output, "ip"})
	if err != nil {
		t.Fatal(err)
	}
	expected := defaultFlags("foo")
	expected.filterExpr = "ip"
	requireFlags(t, output, expected, flags)

	// Multiple args
	flags, err = parseFlags("", []string{"foo", output, "vlan", "and", "ip"})
	if err != nil {
		t.Fatal(err)
	}
	expected = defaultFlags("foo")
	expected.filterExpr = "vlan and ip"
	requireFlags(t, output, expected, flags)
}

func TestFilterRaw(t *testing.T) {
	output := tempOutput(t)

	test := func(args []string, filter []bpf.Instruction) {
		t.Helper()

		flags, err := parseFlags("", append([]string{"foo", output}, args...))
		if err != nil {
			t.Fatal(err)
		}
		expected := defaultFlags("foo")
		expected.filterExpr = strings.Join(args, " ")
		expected.filterOpts.filter = filter
		requireFlags(t, output, expected, flags)
	}

	// Single arg
	test([]string{"1,6 0 0 1"}, []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	})

	// Multiple args
	test([]string{"1,6", "0", "0", "1"}, []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	})

	// Multiple instructions
	test([]string{"2,48 0 0 0,6 0 0 1"}, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.RetConstant{Val: 1},
	})

	// Trailing comma
	test([]string{"1,6 0 0 1,"}, []bpf.Instruction{
		bpf.RetConstant{Val: 1},
	})
}

func TestFilterRawInvalid(t *testing.T) {
	_, err := parsecBPF("3,6 0 0 1")
	if err == nil {
		t.Fatal("invalid instruction count accepted")
	}

	_, err = parsecBPF("1,6 0 0 4294967296")
	if err == nil {
		t.Fatal("overflowy instruction accepted")
	}
}

func TestOptions(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{"-buffer", "1234", "-watermark", "5678", "-q", "-flush", "-actions", "pass,drop", "-linktype", "802.11", "-c", "1000", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultFlags("foo")
	expected.filterOpts.perfPerCPUBuffer = 1234
	expected.filterOpts.perfWatermark = 5678
	expected.quiet = true
	expected.flush = true
	expected.filterOpts.actions = []xdpAction{xdpPass, xdpDrop}
	expected.linkType = layers.LinkTypeIEEE802_11
	expected.maxPackets = 1000

	requireFlags(t, output, expected, flags)
}

func TestActionsFlagUnknown(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{"-actions", "pass,aborted,3", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultFlags("foo")
	expected.filterOpts.actions = []xdpAction{xdpPass, xdpAborted, xdpAction(3)}

	requireFlags(t, output, expected, flags)

	// Hex
	flags, err = parseFlags("", []string{"-actions", "pass,aborted,0xDE", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected = defaultFlags("foo")
	expected.filterOpts.actions = []xdpAction{xdpPass, xdpAborted, xdpAction(0xDE)}

	requireFlags(t, output, expected, flags)
}

func TestActionsFlagWhitespace(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{"-actions", "pass, aborted\t,\n3", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultFlags("foo")
	expected.filterOpts.actions = []xdpAction{xdpPass, xdpAborted, xdpAction(3)}

	requireFlags(t, output, expected, flags)
}

func TestActionsFlagBad(t *testing.T) {
	output := tempOutput(t)

	_, err := parseFlags("", []string{"-actions", "foobar, aborted", "foo", output})
	if err == nil {
		t.Fatal("bad xdp action foobar accepted")
	}
}

func TestLinkTypeUnknown(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{"-linktype", "12", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultFlags("foo")
	expected.linkType = layers.LinkType(12)

	requireFlags(t, output, expected, flags)

	// Hex
	flags, err = parseFlags("", []string{"-linktype", "0xC", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected = defaultFlags("foo")
	expected.linkType = layers.LinkType(0xC)

	requireFlags(t, output, expected, flags)
}

func TestUsage(t *testing.T) {
	flags, err := parseFlags("", []string{"-help"})
	if err != flag.ErrHelp {
		t.Fatal("help flag not handled")
	}

	// Just check we get something
	if flags.Usage() == "" {
		t.Fatal("empty usage")
	}
}

func tempOutput(t *testing.T) string {
	t.Helper()

	output, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}

	output.Close()
	os.Remove(output.Name())

	return output.Name()
}

func defaultFlags(mapPath string) flags {
	return flags{
		mapPath:    mapPath,
		pcapFile:   nil,
		quiet:      false,
		flush:      false,
		linkType:   layers.LinkTypeEthernet,
		filterExpr: "",
		filterOpts: filterOpts{
			perfPerCPUBuffer: 8192,
			perfWatermark:    1,
			actions:          []xdpAction{},
		},
	}
}

func requireFlags(tb testing.TB, output string, expected, actual flags) {
	tb.Helper()

	if actual.pcapFile.Name() != output {
		tb.Fatalf("Expected output %s, got %s\n", output, actual.pcapFile.Name())
	}

	// Pretend output is correct, we already checked it
	expected.pcapFile = actual.pcapFile

	// Don't care about the flagset
	expected.FlagSet = actual.FlagSet

	// No expected filter, expected filter is filterExpr compiled with libpcap
	if expected.filterOpts.filter == nil {
		filter, err := internal.TcpdumpExprToBPF(expected.filterExpr, expected.linkType)
		if err != nil {
			tb.Fatalf("Expected filterExpr %v can't be compiled: %v\n", expected.filterExpr, err)
		}

		expected.filterOpts.filter = filter
	}

	if !reflect.DeepEqual(expected, actual) {
		tb.Fatalf("\nExpected: %#v\nGot     : %#v\n\n", expected, actual)
	}
}
