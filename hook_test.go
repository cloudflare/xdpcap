package xdpcap

import (
	"testing"

	"github.com/cilium/ebpf"
)

const (
	elf        = "testdata/xdp_hook.c.elf"
	hookSymbol = "xdpcap_hook"
)

// Test loading an elf with a hook map using ebpf.NewCollection().
func TestHookNewCollection(t *testing.T) {
	hook, err := NewHook("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer hook.Close()

	spec := mustPatchSpec(t, hook)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
}

// Test loading an elf with a hook map using ebpf.CollectionSpec.LoadAndReplace(),
// which didn't always work: https://github.com/cilium/ebpf/commit/04b5c2a901f3bcfa7d7a13c59f7c1c556f2f3d5f
func TestHookLoadAndReplace(t *testing.T) {
	test := func(t *testing.T, hook *Hook) {
		spec := mustPatchSpec(t, hook)

		var objs struct {
			// Works for both programs that do and don't use the hook.
			Hook   *ebpf.Program `ebpf:"xdp_hook"`
			NoHook *ebpf.Program `ebpf:"xdp_nohook"`
		}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			t.Fatal(err)
		}
		defer objs.Hook.Close()
		defer objs.NoHook.Close()
	}

	t.Run("nil", func(t *testing.T) {
		test(t, nil)
	})

	t.Run("not-nil", func(t *testing.T) {
		hook, err := NewHook("foo")
		if err != nil {
			t.Fatal(err)
		}
		defer hook.Close()

		test(t, hook)
	})
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

func mustPatchSpec(tb testing.TB, hook *Hook) *ebpf.CollectionSpec {
	spec, err := ebpf.LoadCollectionSpec(elf)
	if err != nil {
		tb.Fatal(err)
	}

	err = hook.Patch(spec, hookSymbol)
	if err != nil {
		tb.Fatal(err)
	}

	return spec
}
