package main

import (
	"github.com/cloudflare/xdpcap"

	"github.com/newtools/ebpf"
	"github.com/pkg/errors"
)

type packet struct {
	action xdpAction
	data   []byte
}

var perfMapSpec = ebpf.MapSpec{
	Name: "xdpcap_perf",
	Type: ebpf.PerfEventArray,
}

type filterOpts struct {
	perfPerCPUBuffer int
	perfWatermark    int
}

// filter represents a filter loaded into the kernel
type filter struct {
	hookMap *ebpf.Map
	reader  *ebpf.PerfReader

	programs map[xdpAction]*program

	actions []xdpAction
}

// newFilter creates a filter from a tcpdump / libpcap filter expression
func newFilter(hookMapPath string, expr string, opts filterOpts) (*filter, error) {
	hookMap, err := ebpf.LoadPinnedMap(hookMapPath)
	if err != nil {
		return nil, errors.Wrapf(err, "loading hook map")
	}

	return newFilterWithMap(hookMap, expr, opts)
}

// newFilterWithMap creates a filter from a tcpdump / libpcap filter expression
func newFilterWithMap(hookMap *ebpf.Map, expr string, opts filterOpts) (*filter, error) {
	insns, err := tcpdumpExprToBPF(expr)
	if err != nil {
		return nil, errors.Wrap(err, "converting filter expression to cBPF")
	}

	err = xdpcap.HookMapABI.Check(hookMap)
	if err != nil {
		return nil, errors.Wrap(err, "invalid hook map ABI")
	}

	perfMap, err := ebpf.NewMap(&perfMapSpec)
	if err != nil {
		return nil, errors.Wrap(err, "creating perf map")
	}

	reader, err := ebpf.NewPerfReader(ebpf.PerfReaderOptions{
		Map:          perfMap,
		PerCPUBuffer: opts.perfPerCPUBuffer,
		Watermark:    opts.perfWatermark,
	})
	if err != nil {
		return nil, errors.Wrap(err, "can't create perf event reader")
	}

	filter := &filter{
		hookMap:  hookMap,
		reader:   reader,
		programs: make(map[xdpAction]*program),
		actions:  []xdpAction{},
	}

	// Attach a prog for every index of the map
	for i := 0; i < int(hookMap.ABI().MaxEntries); i++ {
		action := xdpAction(i)
		filter.actions = append(filter.actions, action)

		program, err := newProgram(insns, action, perfMap)
		if err != nil {
			return nil, errors.Wrapf(err, "loading filter program for %v", action)
		}

		err = attachProg(hookMap, program.program.FD(), action)
		if err != nil {
			// close and detach any previously successfully attached programs, but not this one
			filter.close()
			return nil, err
		}

		filter.programs[action] = program
	}

	return filter, nil
}

// no good way to check if a program is already attached, as Create() doesn't work on prog array maps
// We could check if values are present for keys, but that's not atomic with writing a value anyways
func attachProg(hookMap *ebpf.Map, fd int, action xdpAction) error {
	err := hookMap.Put(int32(action), int32(fd))
	if err != nil {
		return errors.Wrap(err, "attaching filter programs")
	}

	return nil
}

func (f *filter) close() error {
	// If an error occurs, return the last one
	var err error

	for action, prog := range f.programs {
		err = f.hookMap.Delete(int32(action))

		prog.close()
	}

	f.reader.FlushAndClose()

	return errors.Wrap(err, "detaching filter programs")
}

func (f *filter) forward(packets chan<- packet, errs chan<- error) {
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

			action := xdpAction(nativeEndian.Uint64(pkt.Data[:8]))
			length := int(nativeEndian.Uint64(pkt.Data[8:16]))
			data := pkt.Data[16:]

			if len(pkt.Data) < length {
				errs <- errors.New("perf packet truncated")
				continue
			}

			data = data[:length]

			packets <- packet{
				action: action,
				data:   data,
			}

		case err := <-f.reader.Error:
			errs <- err
		}
	}
}

func (f *filter) metrics() (map[xdpAction]metrics, error) {
	metrics := make(map[xdpAction]metrics, len(f.programs))

	for action, prog := range f.programs {
		progMetrics, err := prog.metrics()
		if err != nil {
			return nil, errors.Wrapf(err, "collecting metrics from program %v", action)
		}

		metrics[action] = progMetrics
	}

	return metrics, nil
}
