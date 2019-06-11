package main

import (
	"flag"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestArgs(t *testing.T) {
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

	// Three args
	flags, err = parseFlags("", []string{"foo", output, "bar"})
	if err != nil {
		t.Fatal(err)
	}
	expected := defaultFlags("foo")
	expected.filterExpr = "bar"
	requireFlags(t, output, expected, flags)

	// Four args
	flags, err = parseFlags("", []string{"foo", output, "bar", "shoe"})
	if err != nil {
		t.Fatal(err)
	}
	expected = defaultFlags("foo")
	expected.filterExpr = "bar shoe"
	requireFlags(t, output, expected, flags)
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

func TestOptions(t *testing.T) {
	output := tempOutput(t)

	flags, err := parseFlags("", []string{"-buffer", "1234", "-watermark", "5678", "-q", "-flush", "-actions", "pass,drop", "foo", output})
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultFlags("foo")
	expected.filterOpts.perfPerCPUBuffer = 1234
	expected.filterOpts.perfWatermark = 5678
	expected.quiet = true
	expected.flush = true
	expected.filterOpts.actions = []xdpAction{xdpPass, xdpDrop}

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

	if !reflect.DeepEqual(expected, actual) {
		tb.Fatalf("\nExpected: %#v\nGot     : %#v\n\n", expected, actual)
	}
}
