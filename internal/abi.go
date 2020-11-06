package internal

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

// HookMapSpec is the ABI of the underlying prog map created
var HookMapSpec = &ebpf.MapSpec{
	Type:       ebpf.ProgramArray,
	KeySize:    4, // sizeof(int)
	ValueSize:  4, // sizeof(int)
	MaxEntries: 4, // current number of XDP actions
}

// CheckHookMap checks the given map against HookMapABI to have appropriate values
// Only checks Type, KeySize, ValueSize
func CheckHookMap(m *ebpf.Map) error {
	if m.Type() != HookMapSpec.Type {
		return errors.Errorf("expected map type %s, have %s", HookMapSpec.Type, m.Type())
	}

	if m.KeySize() != HookMapSpec.KeySize {
		return errors.Errorf("expected key size to be %d, have %d", HookMapSpec.KeySize, m.KeySize())
	}

	if m.ValueSize() != HookMapSpec.ValueSize {
		return errors.Errorf("expected value size to be %d, have %d", HookMapSpec.ValueSize, m.ValueSize())
	}

	return nil
}
