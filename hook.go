package xdpcap

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/pkg/errors"
)

// Hook represents an xdpcap hook point.
// This hook can be reused with several programs.
type Hook struct {
	hookMap  *ebpf.Map
	fileName string
}

// NewHook creates a new Hook, that can be Pin()'d to fileName.
// fileName must be inside a bpffs
func NewHook(fileName string) (*Hook, error) {
	spec := internal.HookMapSpec.Copy()
	spec.Name = filepath.Base(fileName)

	hookMap, err := ebpf.NewMap(spec)
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

// Map returns the underlying ebpf.Map that this hook uses.
func (h *Hook) Map() *ebpf.Map {
	return h.hookMap
}

// PatchOpts sets MapReplacements in opts to replace references to hookMapSymbol to use this hook.
//
// This function is a no-op if called on a nil Hook.
// opts can be nil.
//
// opts is modified in place, and returned for convenience.
func (h *Hook) PatchOpts(opts ebpf.CollectionOptions, hookMapSymbol string) ebpf.CollectionOptions {
	if h == nil {
		return opts
	}

	if opts.MapReplacements == nil {
		opts.MapReplacements = make(map[string]*ebpf.Map)
	}

	opts.MapReplacements[hookMapSymbol] = h.hookMap
	return opts
}

// Patch edits all programs in the spec that refer to hookMapSymbol to use this hook.
//
// This function is a no-op if called on a nil Hook.
//
// Deprecated: Use Hook.PatchOpts instead, or use Hook.Map() and set ebpf.CollectionOptions.MapReplacements.
func (h *Hook) Patch(spec *ebpf.CollectionSpec, hookMapSymbol string) error {
	if h == nil {
		return nil
	}

	// Old spec.RewriteMaps() method, which was removed upstream.
	// https://github.com/cilium/ebpf/blob/v0.14.0/collection.go#L83
	// have we seen a program that uses this symbol / map
	seen := false
	for progName, progSpec := range spec.Programs {
		err := progSpec.Instructions.AssociateMap(hookMapSymbol, h.hookMap)

		switch {
		case err == nil:
			seen = true

		case errors.Is(err, asm.ErrUnreferencedSymbol):
			// Not all programs need to use the map

		default:
			return fmt.Errorf("program %s: %w", progName, err)
		}
	}

	if !seen {
		return fmt.Errorf("map %s not referenced by any programs", hookMapSymbol)
	}

	// Prevent NewCollection from creating rewritten maps
	delete(spec.Maps, hookMapSymbol)

	return nil
}
