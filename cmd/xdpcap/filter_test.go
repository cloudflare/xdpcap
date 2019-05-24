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
}

func TestMain(m *testing.M) {
	err := unlimitLockedMemory()
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestEmptyExpr(t *testing.T) {
	filter := mustNew(t, "", 4, testOpts)
	defer filter.close()
	discardPerf(t, filter)

	checkActions(t, filter, []byte{})
}

func TestUnknownAction(t *testing.T) {
	// progs with actions from 0-9. Only 0-3 are used currently.
	filter := mustNew(t, "", 10, testOpts)
	defer filter.close()
	discardPerf(t, filter)

	checkActions(t, filter, []byte{})
}

func TestMetrics(t *testing.T) {
	filter := mustNew(t, "ether[0] == 2", 4, testOpts)
	defer filter.close()
	discardPerf(t, filter)

	// Match - 1 packet received, 1 matched
	checkActions(t, filter, []byte{2})

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
	checkActions(t, filter, []byte{3})

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
	filter := mustNew(t, "ether[0] == 0xde", 1, testOpts)
	defer filter.close()

	packets := make(chan packet)
	errors := make(chan error)

	go filter.forward(packets, errors)

	// Match
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}
	checkActions(t, filter, pktData)

	filter.close()

	select {
	case pkt := <-packets:
		if len(pkt.data) < len(pktData) {
			t.Fatal("unexpected packet length")
		}

		if !bytes.Equal(pktData, pkt.data[:len(pktData)]) {
			t.Fatal("unexpected packet contents")
		}

		return

	case err := <-errors:
		t.Fatal(err)
	}
}

// checkActions checks that all programs return their expected action, and the packet isn't modified
// Packet is 0 padded to min ethernet length
func checkActions(t *testing.T, filter *filter, in []byte) {
	if len(in) < 14 {
		t := make([]byte, 14)
		copy(t, in)
		in = t
	}

	for action, prog := range filter.programs {
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

func hookMap(t *testing.T, entries uint32) *ebpf.Map {
	t.Helper()

	hookMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       xdpcap.HookMapABI.Type,
		KeySize:    xdpcap.HookMapABI.KeySize,
		ValueSize:  xdpcap.HookMapABI.ValueSize,
		MaxEntries: entries,
	})

	if err != nil {
		t.Fatal(err)
	}

	return hookMap
}

func mustNew(t *testing.T, expr string, entries uint32, opts filterOpts) *filter {
	t.Helper()

	filter, err := newFilterWithMap(hookMap(t, entries), expr, opts)
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
