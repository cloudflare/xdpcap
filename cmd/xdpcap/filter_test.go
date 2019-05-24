package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/cloudflare/xdpcap"

	"github.com/newtools/ebpf"
)

var testOpts = filterOpts{
	perfPerCPUBuffer: 8192,
	perfWatermark:    4096,
	actions:          []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx},
}

func TestMain(m *testing.M) {
	err := unlimitLockedMemory()
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestEmptyExpr(t *testing.T) {
	filter := mustNew(t, "", testOpts)
	defer filter.close()
	discardPerf(t, filter)

	checkActions(t, testOpts, filter, []byte{})
}

func TestUnknownAction(t *testing.T) {
	// progs with actions from 0-9. Only 0-3 are used currently.
	opts := testOpts
	opts.actions = []xdpAction{}
	for i := 0; i < 10; i++ {
		opts.actions = append(opts.actions, xdpAction(i))
	}

	filter := mustNew(t, "", opts)
	defer filter.close()
	discardPerf(t, filter)

	checkActions(t, opts, filter, []byte{})
}

func TestMetrics(t *testing.T) {
	filter := mustNew(t, "ether[0] == 2", testOpts)
	defer filter.close()
	discardPerf(t, filter)

	// Match - 1 packet received, 1 matched
	checkActions(t, testOpts, filter, []byte{2})

	metrics, err := filter.metrics()
	if err != nil {
		t.Fatal(err)
	}
	for action, progMetrics := range metrics {
		if progMetrics.receivedPackets != 1 {
			t.Fatalf("filter %v receivedPackets expected 1, got %d", action, progMetrics.receivedPackets)
		}

		if progMetrics.matchedPackets != 1 {
			t.Fatalf("filter %v matchedPackets expected 1, got %d", action, progMetrics.matchedPackets)
		}

		if progMetrics.perfOutputErrors != 0 {
			t.Fatalf("filter %v perfOutputErrors expected 0, got %d", action, progMetrics.perfOutputErrors)
		}
	}

	// No match - 2 packet received, 1 matched
	checkActions(t, testOpts, filter, []byte{3})

	metrics, err = filter.metrics()
	if err != nil {
		t.Fatal(err)
	}
	for action, progMetrics := range metrics {
		if progMetrics.receivedPackets != 2 {
			t.Fatalf("filter %v receivedPackets expected 2, got %d", action, progMetrics.receivedPackets)
		}

		if progMetrics.matchedPackets != 1 {
			t.Fatalf("filter %v matchedPackets expected 1, got %d", action, progMetrics.matchedPackets)
		}

		if progMetrics.perfOutputErrors != 0 {
			t.Fatalf("filter %v perfOutputErrors expected 0, got %d", action, progMetrics.perfOutputErrors)
		}
	}
}

func TestPerf(t *testing.T) {
	filter := mustNew(t, "ether[0] == 0xde", testOpts)
	defer filter.close()

	// Buffered so we can close the filter (which FlushAndCloses the perf reader),
	// without having to concurrently read from packets
	packets := make(chan packet, len(testOpts.actions))
	errors := make(chan error)

	go filter.forward(packets, errors)

	// Match
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}
	checkActions(t, testOpts, filter, pktData)

	filter.close()

	for _, action := range testOpts.actions {
		select {
		case pkt := <-packets:
			if len(pkt.data) < len(pktData) {
				t.Fatalf("action %v: unexpected packet length", action)
			}

			if !bytes.Equal(pktData, pkt.data[:len(pktData)]) {
				t.Fatalf("action %v: unexpected packet contents", action)
			}

			return

		case err := <-errors:
			t.Fatal(err)
		}
	}
}

// checkActions checks that all programs return their expected action, and the packet isn't modified
// Packet is 0 padded to min ethernet length
func checkActions(t *testing.T, opts filterOpts, filter *filter, in []byte) {
	if len(in) < 14 {
		t := make([]byte, 14)
		copy(t, in)
		in = t
	}

	// Make sure the filter created the correct programs
	if len(opts.actions) != len(filter.programs) {
		t.Fatalf("mismatched number of actions and attached programs")
	}

	for _, action := range opts.actions {
		prog, ok := filter.programs[action]
		if !ok {
			t.Fatalf("filter missing program for action %v", prog)
		}

		ret, out, err := prog.program.Test(in)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(in, out) {
			t.Fatalf("Program modified input:\nIn: %v\nOut: %v\n", in, out)
		}

		retAction := xdpAction(ret)

		if retAction != action {
			t.Fatalf("Program returned %v, expected %v\n", retAction, action)
		}
	}
}

func hookMap(t *testing.T, entries int) *ebpf.Map {
	t.Helper()

	hookMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       xdpcap.HookMapABI.Type,
		KeySize:    xdpcap.HookMapABI.KeySize,
		ValueSize:  xdpcap.HookMapABI.ValueSize,
		MaxEntries: uint32(entries),
	})

	if err != nil {
		t.Fatal(err)
	}

	return hookMap
}

func mustNew(t *testing.T, expr string, opts filterOpts) *filter {
	t.Helper()

	filter, err := newFilterWithMap(hookMap(t, len(opts.actions)), expr, opts)
	if err != nil {
		t.Fatal(err)
	}

	return filter
}

// read and discard perf packets & errors
// required to Filter.Close() for tests that don't care about perf
func discardPerf(t *testing.T, filter *filter) {
	t.Helper()

	packets := make(chan packet)
	errors := make(chan error)

	go filter.forward(packets, errors)
	go func() {
		for {
			select {
			case <-packets:
			case <-errors:
			}
		}
	}()
}
