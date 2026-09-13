package authoring

import (
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// The Go-authored maps must reproduce the committed ir.json `mappings` fragment
// EXACTLY (semantic equality via Canonical — sorted-key compact, the form the
// engine's behaviour depends on). This is the phase-1 proof that the Go
// authoring layer can replace the Python one with zero behaviour change; the
// remaining maps follow the same pattern, then Python is retired (DX_DFIR #188).
func TestPilotMapsMatchCommittedIR(t *testing.T) {
	doc, err := ir.Load()
	if err != nil {
		t.Fatalf("load IR: %v", err)
	}
	for _, key := range []string{"esedump_srum", "prefetch_dump"} {
		e, ok := Registry[key]
		if !ok {
			t.Fatalf("no Go-authored map %q registered", key)
		}
		want := ir.Get(doc, "mappings", key)
		if want == nil {
			t.Fatalf("committed ir.json has no mappings[%q]", key)
		}
		wc, err := pyjson.Canonical(want)
		if err != nil {
			t.Fatalf("canonical(want %q): %v", key, err)
		}
		gc, err := pyjson.Canonical(e.Encode())
		if err != nil {
			t.Fatalf("canonical(go %q): %v", key, err)
		}
		if gc != wc {
			t.Errorf("map %q: Go authoring != committed IR\n  go:   %s\n  want: %s", key, gc, wc)
		}
	}
}
