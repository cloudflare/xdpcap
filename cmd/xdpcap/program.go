package main

import (
	"github.com/cloudflare/cbpfc"
	"github.com/newtools/ebpf"
	"github.com/newtools/ebpf/asm"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

const BPF_F_CURRENT_CPU int64 = 0xFFFFFFFF

type metrics [3]uint64

type metric int

const (
	receivedPackets metric = iota
	matchedPackets
	perfOutputErrors
)

// map for exporting metrics
var metricsSpec = ebpf.MapSpec{
	Name:       "xdpcap_metrics",
	Type:       ebpf.PerCPUArray,
	KeySize:    4,
	ValueSize:  uint32(len(metrics{}) * 8),
	MaxEntries: 1,
}

// abi of map for exporting packets
var perfABI = ebpf.MapABI{
	Type: ebpf.PerfEventArray,
}

// program represents a filter program for a particular XDP action
type program struct {
	program *ebpf.Program
	metrics *ebpf.Map
}

// newProgram builds an eBPF program that copies packets matching a cBPF program to userspace via perf
func newProgram(filter []bpf.Instruction, action XDPAction, perfMap *ebpf.Map) (*program, error) {
	metricsMap, err := ebpf.NewMap(&metricsSpec)
	if err != nil {
		return nil, errors.Wrap(err, "creating metrics map")
	}

	err = perfABI.Check(perfMap)
	if err != nil {
		return nil, errors.Wrap(err, "invalid perf map ABI")
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
		asm.MapLookupElement.Call(),

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
		asm.PerfEventOutput.Call(),

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

	prog, err := ebpf.NewProgram(
		&ebpf.ProgramSpec{
			Name:         "xdpcap_filter",
			Type:         ebpf.XDP,
			Instructions: insns,
			License:      "GPL",
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "loading filter")
	}

	return &program{
		program: prog,
		metrics: metricsMap,
	}, nil
}

func (p *program) Close() {
	p.metrics.Close()
	p.program.Close()
}

func (p *program) Metrics() (metrics, error) {
	perCpuMetrics := []metrics{}

	ok, err := p.metrics.Get(uint32(0), &perCpuMetrics)
	if err != nil {
		return metrics{}, errors.Wrap(err, "accessing metrics map")
	} else if !ok {
		return metrics{}, errors.New("metrics map key doesn't exist")
	}

	metrics := metrics{}
	for _, cpu := range perCpuMetrics {
		for i, m := range cpu {
			metrics[i] += m
		}
	}

	return metrics, nil
}
