package internal

import (
	"github.com/cilium/ebpf"
	"github.com/cloudflare/xdpcap"
	"github.com/pkg/errors"
)

// CheckHookMap checks the given map against HookMapABI to have appropriate values
// Only checks Type, KeySize, ValueSize
func CheckHookMap(m *ebpf.Map) error {
	abi := m.ABI()
	if abi.Type != xdpcap.HookMapABI.Type {
		return errors.Errorf("expected map type %s, have %s", xdpcap.HookMapABI.Type, abi.Type)
	}

	if abi.KeySize != xdpcap.HookMapABI.KeySize {
		return errors.Errorf("expected key size to be %d, have %d", xdpcap.HookMapABI.KeySize, abi.KeySize)
	}

	if abi.ValueSize != xdpcap.HookMapABI.ValueSize {
		return errors.Errorf("expected value size to be %d, have %d", xdpcap.HookMapABI.ValueSize, abi.ValueSize)
	}

	return nil
}
