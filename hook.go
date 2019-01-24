package xdpcap

import (
	"os"
	"path/filepath"

	"github.com/newtools/ebpf"
	"github.com/pkg/errors"
)

// synmbol name of the hook map
const hookMapSymbol = "xdpcap_hook"

var hookMapABI = ebpf.MapABI{
	Type:      ebpf.ProgramArray,
	KeySize:   4, // sizeof(int)
	ValueSize: 4, // sizeof(int)
}

var collectionAbi = ebpf.CollectionABI{
	Maps: map[string]*ebpf.MapABI{
		hookMapSymbol: &hookMapABI,
	},
}

type Hook struct {
	hookMap  *ebpf.Map
	fileName string
}

// NewHook creates a new Hook, that can be Pin()'d to fileName.
// fileName must be inside a bpffs
func NewHook(fileName string) (*Hook, error) {
	hookMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       ebpf.SanitizeName(filepath.Base(fileName), '_'),
		Type:       hookMapABI.Type,
		KeySize:    hookMapABI.KeySize,
		ValueSize:  hookMapABI.ValueSize,
		MaxEntries: 4, // current number of XDP actions
	})
	if err != nil {
		return nil, errors.Wrap(err, "creating hook map")
	}

	return &Hook{
		hookMap:  hookMap,
		fileName: fileName,
	}, nil
}

// Close releases any resources held
// It does not Rm()
func (h *Hook) Close() error {
	return h.hookMap.Close()
}

// Pin persists the underlying map to a file, overwriting it if it already exists
func (h *Hook) Pin() error {
	// Pin() fails if the file already exists, try to remove it first
	h.Rm()
	return errors.Wrapf(h.hookMap.Pin(h.fileName), "file %s", h.fileName)
}

// Rm deletes files created by Pin()
func (h *Hook) Rm() error {
	return errors.Wrapf(os.Remove(h.fileName), "file %s", h.fileName)
}

// Patch edits all programs in the spec that refer to a hook to use this hook
func (h *Hook) Patch(spec *ebpf.CollectionSpec) error {
	err := collectionAbi.CheckSpec(spec)
	if err != nil {
		return err
	}

	// We can't specify to use an already existing map in a spec, so:
	// - Rewrite the hook map symbol of every program
	// - Remove the map from spec (so it isn't created later on)
	for progName, progSpec := range spec.Programs {
		err = ebpf.Edit(&progSpec.Instructions).RewriteMap(hookMapSymbol, h.hookMap)

		// Not all programs need to use the hook
		if ebpf.IsUnreferencedSymbol(err) {
			continue
		}

		if err != nil {
			return errors.Wrapf(err, "program %s", progName)
		}
	}

	delete(spec.Maps, hookMapSymbol)

	return nil
}
