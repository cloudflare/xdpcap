package main

import (
	"github.com/cloudflare/xdpcap"

	"github.com/newtools/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

type Packet struct {
	Action XDPAction
	Data   []byte
}

type Metrics struct {
	ReceivedPackets  uint64
	MatchedPackets   uint64
	PerfOutputErrors uint64
}

var perfMapSpec = ebpf.MapSpec{
	Name: "xdpcap_perf",
	Type: ebpf.PerfEventArray,
}

type FilterOpts struct {
	PerfPerCPUBuffer int
	PerfWatermark    int
}

// filter represents a filter loaded into the kernel
type Filter struct {
	hookMap *ebpf.Map
	reader  *ebpf.PerfReader

	programs map[XDPAction]*program

	actions []XDPAction
}

// NewFilter creates a filter from a tcpdump / libpcap filter expression
func NewFilter(hookMapPath string, expr string, opts FilterOpts) (*Filter, error) {
	hookMap, err := ebpf.LoadPinnedMap(hookMapPath)
	if err != nil {
		return nil, errors.Wrapf(err, "loading hook map")
	}

	return NewFilterWithMap(hookMap, expr, opts)
}

// NewFilterFromExpr creates a filter from a tcpdump / libpcap filter expression
func NewFilterWithMap(hookMap *ebpf.Map, expr string, opts FilterOpts) (*Filter, error) {
	insns, err := tcpdumpExprToBPF(expr)
	if err != nil {
		return nil, errors.Wrap(err, "converting filter expression to cBPF")
	}

	return newFilter(hookMap, insns, opts)
}

func newFilter(hookMap *ebpf.Map, insns []bpf.Instruction, opts FilterOpts) (*Filter, error) {
	err := xdpcap.HookMapABI.Check(hookMap)
	if err != nil {
		return nil, errors.Wrap(err, "invalid hook map ABI")
	}

	perfMap, err := ebpf.NewMap(&perfMapSpec)
	if err != nil {
		return nil, errors.Wrap(err, "creating perf map")
	}

	reader, err := ebpf.NewPerfReader(ebpf.PerfReaderOptions{
		Map:          perfMap,
		PerCPUBuffer: opts.PerfPerCPUBuffer,
		Watermark:    opts.PerfWatermark,
	})
	if err != nil {
		return nil, errors.Wrap(err, "can't create perf event reader")
	}

	filter := &Filter{
		hookMap:  hookMap,
		reader:   reader,
		programs: make(map[XDPAction]*program),
		actions:  []XDPAction{},
	}

	// Attach a prog for every index of the map
	for i := 0; i < int(hookMap.ABI().MaxEntries); i++ {
		action := XDPAction(i)
		filter.actions = append(filter.actions, action)

		program, err := newProgram(insns, action, perfMap)
		if err != nil {
			return nil, errors.Wrapf(err, "loading filter program for %v", action)
		}

		err = attachProg(hookMap, program.program.FD(), action)
		if err != nil {
			// close and detach any previously successfully attached programs, but not this one
			filter.Close()
			return nil, err
		}

		filter.programs[action] = program
	}

	return filter, nil
}

// no good way to check if a program is already attached, as Create() doesn't work on prog array maps
// We could check if values are present for keys, but that's not atomic with writing a value anyways
func attachProg(hookMap *ebpf.Map, fd int, action XDPAction) error {
	err := hookMap.Put(int32(action), int32(fd))
	if err != nil {
		return errors.Wrap(err, "attaching filter programs")
	}

	return nil
}

func (f *Filter) Close() error {
	// If an error occurs, return the last one
	var err error

	for action, prog := range f.programs {
		err = f.hookMap.Delete(int32(action))

		prog.Close()
	}

	f.reader.FlushAndClose()

	return errors.Wrap(err, "detaching filter programs")
}

func (f *Filter) Actions() []XDPAction {
	return f.actions
}

func (f *Filter) Forward(packets chan<- Packet, errs chan<- error) {
	for {
		select {
		case pkt, ok := <-f.reader.Samples:
			if !ok {
				return
			}

			// The sample format is as follows:
			// <u64: action> <u64: length> <byte * length: raw packet including L2 headers> <padding to 64bits>
			if len(pkt.Data) < 16 {
				errs <- errors.New("perf packet data < 16 bytes")
				continue
			}

			action := XDPAction(nativeEndian.Uint64(pkt.Data[:8]))
			length := int(nativeEndian.Uint64(pkt.Data[8:16]))
			data := pkt.Data[16:]

			if len(pkt.Data) < length {
				errs <- errors.New("perf packet truncated")
				continue
			}

			data = data[:length]

			packets <- Packet{
				Action: action,
				Data:   data,
			}

		case err := <-f.reader.Error:
			errs <- err
		}
	}
}

func (f *Filter) Metrics() (map[XDPAction]Metrics, error) {
	metrics := make(map[XDPAction]Metrics, len(f.programs))

	for action, prog := range f.programs {
		progMetrics, err := prog.Metrics()
		if err != nil {
			return nil, errors.Wrapf(err, "collecting metrics from program %v", action)
		}

		metrics[action] = Metrics{
			ReceivedPackets:  progMetrics[receivedPackets],
			MatchedPackets:   progMetrics[matchedPackets],
			PerfOutputErrors: progMetrics[perfOutputErrors],
		}
	}

	return metrics, nil
}
