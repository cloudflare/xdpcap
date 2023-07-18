package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
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

	// Requested actions. If empty or nil, all the actions exposed by the hookMap are used.
	actions []xdpAction
	filter  []bpf.Instruction
}

// filter represents a filter loaded into the kernel
type filter struct {
	hookMap *ebpf.Map
	reader  *perf.Reader

	programs map[xdpAction]*program

	// Actual actions we're capturing for.
	actions []xdpAction
}

// newFilter creates a filter from a tcpdump / libpcap filter expression
func newFilter(hookMapPath string, opts filterOpts) (*filter, error) {
	hookMap, err := ebpf.LoadPinnedMap(hookMapPath, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "loading hook map")
	}

	return newFilterWithMap(hookMap, opts)
}

// newFilterWithMap creates a filter from a tcpdump / libpcap filter expression
func newFilterWithMap(hookMap *ebpf.Map, opts filterOpts) (*filter, error) {
	if len(opts.filter) == 0 {
		return nil, errors.New("at least one filter cBPF instruction required")
	}

	err := internal.CheckHookMap(hookMap)
	if err != nil {
		return nil, errors.Wrap(err, "invalid hook map ABI")
	}

	perfMap, err := ebpf.NewMap(&perfMapSpec)
	if err != nil {
		return nil, errors.Wrap(err, "creating perf map")
	}
	defer perfMap.Close()

	reader, err := perf.NewReaderWithOptions(perfMap, opts.perfPerCPUBuffer, perf.ReaderOptions{
		Watermark: opts.perfWatermark,
	})
	if err != nil {
		return nil, errors.Wrap(err, "can't create perf event reader")
	}

	if len(opts.actions) == 0 {
		// Ignore all other actions in opts
		opts.actions = allActions(hookMap)
	}

	filter := &filter{
		hookMap:  hookMap,
		reader:   reader,
		programs: make(map[xdpAction]*program),
		actions:  opts.actions,
	}

	xdpFragsMode := false
	for i, action := range opts.actions {
		program, err := newProgram(opts.filter, action, perfMap, xdpFragsMode)
		if err != nil {
			return nil, errors.Wrapf(err, "loading filter program for %v", action)
		}

		err = attachProg(hookMap, program.program.FD(), action)
		if errors.Is(err, unix.EINVAL) && i == 0 {
			// attempt to load first action in XDP frags mode and retry attaching
			// if this doesn't work then there is underlying issue that is not
			// related to the hook being attached in XDP frags mode and we make
			// sure to return the original attachment error.
			xdpFragsMode = true

			var programErr error
			if program, programErr = newProgram(opts.filter, action, perfMap, xdpFragsMode); programErr != nil {
				return nil, errors.Wrapf(programErr, "loading filter program in XDP frags mode for %v", action)
			}

			if attachProg(hookMap, program.program.FD(), action) == nil {
				fmt.Fprintf(os.Stderr, "attaching filter actions in XDP frags mode\n")
				err = nil
			}
		}

		if err != nil {
			// close and detach any previously successfully attached programs, but not this one
			filter.close()
			return nil, err
		}

		filter.programs[action] = program
	}

	return filter, nil
}

// allActions returns every action exposed by the map
func allActions(hookMap *ebpf.Map) []xdpAction {
	actions := []xdpAction{}

	for i := 0; i < int(hookMap.MaxEntries()); i++ {
		actions = append(actions, xdpAction(i))
	}

	return actions
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

	f.reader.Close()

	return errors.Wrap(err, "detaching filter programs")
}

var errFilterClosed = errors.New("filter closed")

// Returns errFilterClosed if the filter has been closed
func (f *filter) read() (packet, error) {
	record, err := f.reader.Read()
	switch {
	case errors.Is(err, perf.ErrClosed):
		return packet{}, errFilterClosed
	case err != nil:
		return packet{}, err
	}

	if record.LostSamples > 0 {
		return packet{}, errors.Errorf("lost %d packets", record.LostSamples)
	}

	raw := record.RawSample

	// The sample format is as follows:
	// <u64: action> <u64: length> <byte * length: raw packet including L2 headers> <padding to 64bits>
	if len(raw) < 16 {
		return packet{}, errors.New("perf packet data < 16 bytes")
	}

	action := xdpAction(nativeEndian.Uint64(raw[:8]))
	length := int(nativeEndian.Uint64(raw[8:16]))
	data := raw[16:]

	if len(data) < length {
		return packet{}, errors.New("perf packet truncated")
	}

	return packet{
		action: action,
		data:   data[:length],
	}, nil
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
