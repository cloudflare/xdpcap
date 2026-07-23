package xdpcap

import (
	"maps"
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

func TestHookPatchOpts(t *testing.T) {
	hook, err := NewHook("foo")
	if err != nil {
		t.Fatal(err)
	}
	defer hook.Close()

	optsWithMaps := func(maps map[string]*ebpf.Map) ebpf.CollectionOptions {
		return ebpf.CollectionOptions{
			MapReplacements: maps,
		}
	}

	for name, tc := range map[string]struct {
		opts ebpf.CollectionOptions
		hook *Hook

		expectedOpts ebpf.CollectionOptions
	}{
		"hook-nil": {},
		"hook-nil-opts": {
			opts: optsWithMaps(map[string]*ebpf.Map{"bar": nil}),

			expectedOpts: optsWithMaps(map[string]*ebpf.Map{"bar": nil}),
		},
		"opts-empty": {
			opts: ebpf.CollectionOptions{},
			hook: hook,

			expectedOpts: optsWithMaps(map[string]*ebpf.Map{hookSymbol: hook.Map()}),
		},
		"opts-existing": {
			opts: optsWithMaps(map[string]*ebpf.Map{"bar": nil}),
			hook: hook,

			expectedOpts: optsWithMaps(map[string]*ebpf.Map{"bar": nil, hookSymbol: hook.Map()}),
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := tc.hook.PatchOpts(tc.opts, hookSymbol)
			if !maps.Equal(tc.expectedOpts.MapReplacements, opts.MapReplacements) {
				t.Fatalf("unexpected map replacements, want %v got %v", tc.expectedOpts.MapReplacements, opts.MapReplacements)
			}

			if len(tc.opts.MapReplacements) != 0 {
				// When there are existing MapReplacements,
				// loading will fail because no programs reference those maps.
				return
			}

			spec, err := ebpf.LoadCollectionSpec(elf)
			if err != nil {
				t.Fatal(err)
			}

			coll, err := ebpf.NewCollectionWithOptions(spec, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer coll.Close()
		})
	}
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
