package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const BPF_F_CURRENT_CPU int64 = 0xFFFFFFFF

type rawMetrics [3]uint64

type rawMetric int

const (
	receivedPackets rawMetric = iota
	matchedPackets
	perfOutputErrors
)

type metrics struct {
	receivedPackets  uint64
	matchedPackets   uint64
	perfOutputErrors uint64
}

// map for exporting metrics
var metricsSpec = ebpf.MapSpec{
	Name:       "xdpcap_metrics",
	Type:       ebpf.PerCPUArray,
	KeySize:    4,
	ValueSize:  uint32(len(rawMetrics{}) * 8),
	MaxEntries: 1,
}

// program represents a filter program for a particular XDP action
type program struct {
	program    *ebpf.Program
	metricsMap *ebpf.Map
}

// newProgram builds an eBPF program that copies packets matching a cBPF program to userspace via perf
func newProgram(filter []bpf.Instruction, action xdpAction, perfMap *ebpf.Map, xdpFragsMode bool) (*program, error) {
	metricsMap, err := ebpf.NewMap(&metricsSpec)
	if err != nil {
		return nil, errors.Wrap(err, "creating metrics map")
	}

	if perfMap.Type() != ebpf.PerfEventArray {
		return nil, errors.Errorf("invalid perf map ABI, expected type %s, have %s", ebpf.PerfEventArray, perfMap.Type())
	}

	// Labels of blocks
	const result = "result"
	const exit = "exit"

	ebpfFilter, err := cbpfc.ToEBPF(filter, cbpfc.EBPFOpts{
		PacketStart: asm.R0,
		PacketEnd:   asm.R1,

		Result:      asm.R2,
		ResultLabel: result,

		Working: [4]asm.Register{asm.R2, asm.R3, asm.R4, asm.R5},

		StackOffset: 0,
		LabelPrefix: "filter",
	})
	if err != nil {
		return nil, errors.Wrap(err, "converting cBPF to eBPF")
	}

	insns := asm.Instructions{
		// Save ctx
		asm.Mov.Reg(asm.R6, asm.R1),

		// Get the metrics struct
		// map fd
		asm.LoadMapPtr(asm.R1, metricsMap.FD()),
		// index
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		// call
		asm.FnMapLookupElem.Call(),

		// Check metrics aren't nil
		asm.JEq.Imm(asm.R0, 0, exit),

		// Save metrics
		asm.Mov.Reg(asm.R7, asm.R0),

		// Packet start
		asm.LoadMem(asm.R0, asm.R6, 0, asm.Word),

		// Packet end
		asm.LoadMem(asm.R1, asm.R6, 4, asm.Word),

		// Packet length
		asm.Mov.Reg(asm.R8, asm.R1),
		asm.Sub.Reg(asm.R8, asm.R0),

		// Received packets
		asm.LoadMem(asm.R2, asm.R7, int16(8*receivedPackets), asm.DWord),
		asm.Add.Imm(asm.R2, 1),
		asm.StoreMem(asm.R7, int16(8*receivedPackets), asm.R2, asm.DWord),

		// Fall through to filter
	}

	insns = append(insns, ebpfFilter...)

	insns = append(insns,
		// Packet didn't match filter
		asm.JEq.Imm(asm.R2, 0, exit).Sym(result),

		// Matched packets
		asm.LoadMem(asm.R0, asm.R7, int16(8*matchedPackets), asm.DWord),
		asm.Add.Imm(asm.R0, 1),
		asm.StoreMem(asm.R7, int16(8*matchedPackets), asm.R0, asm.DWord),

		// Perf output
		// ctx
		asm.Mov.Reg(asm.R1, asm.R6),
		// perf map
		asm.LoadMapPtr(asm.R2, perfMap.FD()),
		// flags (len << 32 | BPF_F_CURRENT_CPU)
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.LSh.Imm(asm.R3, 32),
		asm.LoadImm(asm.R0, BPF_F_CURRENT_CPU, asm.DWord),
		asm.Or.Reg(asm.R3, asm.R0),
		// perf output data
		asm.Mov.Reg(asm.R4, asm.R10),
		//   <u64 packet length>
		asm.Add.Imm(asm.R4, -8),
		asm.StoreMem(asm.R4, 0, asm.R8, asm.DWord),
		//   <u64 action>
		asm.Add.Imm(asm.R4, -8),
		asm.StoreImm(asm.R4, 0, int64(action), asm.DWord),
		// sizeof(data)
		asm.Mov.Imm(asm.R5, 2*8),
		// call
		asm.FnPerfEventOutput.Call(),

		// Perf success
		asm.JEq.Imm(asm.R0, 0, exit),

		// Perf output errors
		asm.LoadMem(asm.R0, asm.R7, int16(8*perfOutputErrors), asm.DWord),
		asm.Add.Imm(asm.R0, 1),
		asm.StoreMem(asm.R7, int16(8*perfOutputErrors), asm.R0, asm.DWord),

		// Fall through to exit
	)

	// Exit with original action - always referred to
	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(action)).Sym(exit),
		asm.Return(),
	)

	progSpec := &ebpf.ProgramSpec{
		Name:         "xdpcap_filter",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "GPL",
	}
	if xdpFragsMode {
		progSpec.Flags = progSpec.Flags | unix.BPF_F_XDP_HAS_FRAGS
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return nil, errors.Wrap(err, "loading filter")
	}

	return &program{
		program:    prog,
		metricsMap: metricsMap,
	}, nil
}

func (p *program) close() {
	p.metricsMap.Close()
	p.program.Close()
}

func (p *program) metrics() (metrics, error) {
	perCpuMetrics := []rawMetrics{}

	err := p.metricsMap.Lookup(uint32(0), &perCpuMetrics)
	if err != nil {
		return metrics{}, errors.Wrap(err, "accessing metrics map")
	}

	metrics := metrics{}
	for _, cpu := range perCpuMetrics {
		metrics.receivedPackets += cpu[receivedPackets]
		metrics.matchedPackets += cpu[matchedPackets]
		metrics.perfOutputErrors += cpu[perfOutputErrors]
	}

	return metrics, nil
}
