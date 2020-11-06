package internal

import (
	"testing"

	"github.com/cilium/ebpf"
)

// Test CheckHookMap with valid and invalid HookMap ABI
func TestCheckHookMap(t *testing.T) {
	valid, err := ebpf.NewMap(HookMapSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()

	if err := CheckHookMap(valid); err != nil {
		t.Fatal(err)
	}

	spec := HookMapSpec.Copy()
	spec.Type = ebpf.Array
	inValid, err := ebpf.NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer inValid.Close()

	if CheckHookMap(inValid) == nil {
		t.Fatal("CheckHookMap expected to return error")
	}
}
