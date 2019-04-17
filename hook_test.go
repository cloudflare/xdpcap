package xdpcap

import (
	"testing"

	"github.com/newtools/ebpf"
)

const (
	elf        = "testdata/xdp_hook.c.elf"
	hookSymbol = "xdpcap_hook"
)

// Test loading an elf with a hook map
func TestHook(t *testing.T) {
	hook, err := NewHook("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer hook.Close()

	spec, err := ebpf.LoadCollectionSpec(elf)
	if err != nil {
		t.Fatal(err)
	}

	err = hook.Patch(spec, hookSymbol)
	if err != nil {
		t.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
}

// Test loading an elf that uses a hook without an explicit hook map
func TestNoHook(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(elf)
	if err != nil {
		t.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
}
