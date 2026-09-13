package authoring

import (
	"sort"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// irMappings returns the committed ir.json `mappings` object.
func irMappings(t *testing.T) *pyjson.Object {
	t.Helper()
	doc, err := ir.Load()
	if err != nil {
		t.Fatalf("load IR: %v", err)
	}
	m, ok := ir.Get(doc, "mappings").(*pyjson.Object)
	if !ok {
		t.Fatal("ir.json: mappings is not an object")
	}
	return m
}

// Every Go-authored map must reproduce the committed ir.json `mappings` fragment
// EXACTLY (semantic equality via Canonical — the sorted-key compact form the
// engine's behaviour depends on). This is the per-map correctness gate: a map is
// "ported" only when it matches. Zero behaviour change vs the Python maps.
func TestRegisteredMapsMatchCommittedIR(t *testing.T) {
	m := irMappings(t)
	for _, key := range Keys() {
		key := key
		t.Run(key, func(t *testing.T) {
			want, ok := m.Get(key)
			if !ok {
				t.Fatalf("committed ir.json has no mappings[%q]", key)
			}
			wc, err := pyjson.Canonical(want)
			if err != nil {
				t.Fatalf("canonical(want): %v", err)
			}
			gc, err := pyjson.Canonical(Registry[key].Encode())
			if err != nil {
				t.Fatalf("canonical(go): %v", err)
			}
			if gc != wc {
				t.Errorf("map %q: Go authoring != committed IR\n  go:   %s\n  want: %s", key, gc, wc)
			}
		})
	}
}

// Completeness: every map in the committed IR is authored in Go. The full map
// layer is now ported, so this is a hard invariant — a new Python/IR map with no
// Go authoring fails CI, keeping the Go layer complete until it becomes the sole
// source of truth (phase 3/4). Lists any missing maps to drive the fix.
func TestAllIRMapsAreAuthoredInGo(t *testing.T) {
	m := irMappings(t)
	var missing []string
	for _, key := range m.Keys() {
		if _, ok := Registry[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d IR maps not yet authored in Go: %v", len(missing), missing)
	}
}
