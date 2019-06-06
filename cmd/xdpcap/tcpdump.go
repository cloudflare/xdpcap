package main

import (
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

// tcpdumpExprToBPF converts a tcpdump / libpcap filter expression to cBPF using libpcap
func tcpdumpExprToBPF(filterExpr string, linkType layers.LinkType) ([]bpf.Instruction, error) {
	// We treat any != 0 filter return code as a match
	insns, err := pcap.CompileBPFFilter(linkType, 1, filterExpr)
	if err != nil {
		return nil, errors.Wrap(err, "compiling expression to BPF")
	}

	return pcapInsnToX(insns), nil
}

func pcapInsnToX(insns []pcap.BPFInstruction) []bpf.Instruction {
	xInsns := make([]bpf.Instruction, len(insns))

	for i, insn := range insns {
		xInsns[i] = bpf.RawInstruction{
			Op: insn.Code,
			Jt: insn.Jt,
			Jf: insn.Jf,
			K:  insn.K,
		}.Disassemble()
	}

	return xInsns
}
