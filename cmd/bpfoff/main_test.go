package main

import (
	"math"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

func TestOffsets(t *testing.T) {
	offsets := []uint32{0, 2, 7, 24}

	// UDP tests LoadIndirect handling as filter needs to load IP header length
	filter, err := addOffsets(offsets, "ip and udp port 53")
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true,
		&layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.ParseIP("1.2.3.4"),
			DstIP:    net.ParseIP("5.6.7.8"),
		},
		&layers.UDP{
			SrcPort: 1234,
			DstPort: 53,
		},
		gopacket.Payload([]byte{1, 2, 3, 4}),
	)

	checkOffsets(t, filter, offsets, false,
		&layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.ParseIP("1.2.3.4"),
			DstIP:    net.ParseIP("5.6.7.8"),
		},
		&layers.UDP{
			SrcPort: 1234,
			DstPort: 54,
		},
		gopacket.Payload([]byte{1, 2, 3, 4}),
	)
}

func TestOffsetOrder(t *testing.T) {
	// Large offset first, bigger than length of packets
	// If addOffsets(0 doesn't sort, a small input packet could never match:
	// the large offset filter would run first, making an out of bounds read
	offsets := []uint32{100, 2}

	filter, err := addOffsets(offsets, "ip6 and host dead::beef")
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true,
		&layers.IPv6{
			Version: 6,
			SrcIP:   net.ParseIP("dead::beef"),
			DstIP:   net.ParseIP("beef::afaf"),
		},
	)

	checkOffsets(t, filter, offsets, false,
		&layers.IPv6{
			Version: 6,
			SrcIP:   net.ParseIP("defd::beef"),
			DstIP:   net.ParseIP("beef::afaf"),
		},
	)
}

func TestOffsetOverflow(t *testing.T) {
	offsets := []uint32{math.MaxUint32 - 1}

	// Just big enough
	_, err := addOffsets(offsets, "ip[1] == 4")
	if err != nil {
		t.Fatal(err)
	}

	// Just too small
	_, err = addOffsets(offsets, "ip[2] == 4")
	if err == nil {
		t.Fatal("offset overflow accepted")
	}
}

func TestUnsupportedInsn(t *testing.T) {
	offsets := []uint32{4, 0}

	_, err := withOffsets(offsets, []bpf.Instruction{
		bpf.LoadExtension{},
	})
	if err == nil {
		t.Fatal("extension accepted")
	}

	_, err = withOffsets(offsets, []bpf.Instruction{
		// Load absolute size 3
		bpf.RawInstruction{Op: 0x23},
	})
	if err == nil {
		t.Fatal("bad instruction accepted")
	}
}

func TestRetConstant(t *testing.T) {
	offsets := []uint32{4, 0}

	// match if pkt[0] == 2
	filter, err := withOffsets(offsets, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{2}))
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{1}))
}

func TestRetA(t *testing.T) {
	offsets := []uint32{4, 9, 0}

	// match if pkt[0] != 0
	filter, err := withOffsets(offsets, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.RetA{},
	})
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{2}))
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{0}))
}

func TestLoadAbsolute(t *testing.T) {
	offsets := []uint32{7, 4, 0}

	// match if pkt[6] == 6
	filter, err := withOffsets(offsets, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 6, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{0, 1, 2, 3, 4, 5, 6}))
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{0, 1, 2, 3, 4, 5, 7}))
	// Out of bounds
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{1, 2, 3}))
}

func TestLoadIndirect(t *testing.T) {
	offsets := []uint32{4, 0, 10}

	// match if pkt[pkt[0] + 3] == 7
	filter, err := withOffsets(offsets, []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.TAX{},
		bpf.LoadIndirect{Off: 3, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 7, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{2, 0, 0, 0, 0, 7, 0}))
	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{3, 0, 0, 0, 0, 6, 7}))
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{2, 0, 0, 0, 7, 0, 7}))
	// Out of bounds
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{0}))
}

func TestLoadMemShift(t *testing.T) {
	offsets := []uint32{4, 0, 10}

	// match if pkt[4 * (pkt[2] & 0xf)] == 20
	filter, err := withOffsets(offsets, []bpf.Instruction{
		bpf.LoadMemShift{Off: 2},
		bpf.TXA{},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 20, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{1, 0, 5, 0}))
	checkOffsets(t, filter, offsets, true, gopacket.Payload([]byte{1, 0, 21}))
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{2, 0, 6, 0}))
	// Out of bounds
	checkOffsets(t, filter, offsets, false, gopacket.Payload([]byte{3, 0}))
}

func checkOffsets(tb testing.TB, filter []bpf.Instruction, offsets []uint32, expected bool, packet ...gopacket.SerializableLayer) {
	tb.Helper()

	vm, err := bpf.NewVM(filter)
	if err != nil {
		tb.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, packet...)
	if err != nil {
		tb.Fatal(err)
	}

	for _, offset := range offsets {
		pkt := append(make([]byte, offset), buf.Bytes()...)

		res, err := vm.Run(pkt)
		if err != nil {
			tb.Fatal(err)
		}

		if (res != 0) != expected {
			tb.Fatalf("Offset %v\npacket %v\nfilter %v\n\n", offset, pkt, filter)
		}
	}
}
