package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/cloudflare/xdpcap"

	"github.com/newtools/ebpf"
	"golang.org/x/net/bpf"
)

func testOpts(filter ...bpf.Instruction) filterOpts {
	return filterOpts{
		perfPerCPUBuffer: 8192,
		perfWatermark:    4096,
		actions:          []xdpAction{xdpAborted, xdpDrop, xdpPass, xdpTx},
		filter:           filter,
	}
}

func matchByte(offset, val uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: offset, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: val, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	}
}

func TestMain(m *testing.M) {
	err := unlimitLockedMemory()
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestMissingFilter(t *testing.T) {
	_, err := newFilterWithMap(hookMap(t, 1), testOpts())
	if err == nil {
		t.Fatal("empty filter accepted")
	}
}

func TestUnknownAction(t *testing.T) {
	// progs with actions from 0-9. Only 0-3 are used currently.
	opts := testOpts(bpf.RetConstant{0})
	opts.actions = []xdpAction{}
	for i := 0; i < 10; i++ {
		opts.actions = append(opts.actions, xdpAction(i))
	}

	filter := mustNew(t, opts)
	defer filter.close()
	discardPerf(t, filter)

	checkActions(t, opts.actions, filter, []byte{})
}

func TestAllActions(t *testing.T) {
	opts := testOpts(bpf.RetConstant{3})
	opts.actions = []xdpAction{}

	// progs with actions from 0-9. Only 0-3 are used currently.
	filter, err := newFilterWithMap(hookMap(t, 10), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.close()

	// check all actually used all the slots of the map
	if len(filter.actions) != 10 {
		t.Fatal("xdpAll unexpected number of actions")
	}
	for i := 0; i < 10; i++ {
		if filter.actions[i] != xdpAction(i) {
			t.Fatalf("expected action %v, got %v", xdpAction(i), filter.actions[i])
		}
	}

	discardPerf(t, filter)

	// We've already checked that filter.actions is what we expect
	checkActions(t, filter.actions, filter, []byte{})
}

func TestMetrics(t *testing.T) {
	opts := testOpts(matchByte(0, 2)...)
	filter := mustNew(t, opts)
	defer filter.close()
	discardPerf(t, filter)

	// Match - 1 packet received, 1 matched
	checkActions(t, opts.actions, filter, []byte{2})

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
	checkActions(t, opts.actions, filter, []byte{3})

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
	opts := testOpts(matchByte(0, 0xde)...)
	filter := mustNew(t, opts)
	defer filter.close()

	// Buffered so we can close the filter (which FlushAndCloses the perf reader),
	// without having to concurrently read from packets
	packets := make(chan packet, len(opts.actions))
	errors := make(chan error)

	go filter.forward(packets, errors)

	// Match
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}
	checkActions(t, opts.actions, filter, pktData)

	filter.close()

	for _, action := range opts.actions {
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
// actions should be the original desired actions, and not filter.actions (unless filter.actions is checked beforehand).
func checkActions(t *testing.T, actions []xdpAction, filter *filter, in []byte) {
	if len(in) < 14 {
		t := make([]byte, 14)
		copy(t, in)
		in = t
	}

	// Make sure the filter created the correct programs
	if len(actions) != len(filter.programs) {
		t.Fatalf("mismatched number of actions and attached programs")
	}

	for _, action := range actions {
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

func mustNew(t *testing.T, opts filterOpts) *filter {
	t.Helper()

	filter, err := newFilterWithMap(hookMap(t, len(opts.actions)), opts)
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
