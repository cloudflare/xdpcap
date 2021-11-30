package xdpcap

import (
	"os"
	"path/filepath"

	"github.com/cloudflare/xdpcap/internal"

	"github.com/cilium/ebpf"
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
	spec.Name = ebpf.SanitizeName(filepath.Base(fileName), '_')

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

// Patch edits all programs in the spec that refer to hookMapSymbol to use this hook.
//
// This function is a no-op if called on a nil Hook.
func (h *Hook) Patch(spec *ebpf.CollectionSpec, hookMapSymbol string) error {
	if h == nil {
		return nil
	}

	return spec.RewriteMaps(map[string]*ebpf.Map{
		hookMapSymbol: h.hookMap,
	})
}
