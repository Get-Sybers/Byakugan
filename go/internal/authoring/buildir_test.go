package authoring

import (
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// BuildIR() must reproduce the committed ir.json in full — semantic (Canonical)
// equality, the form the engine's behaviour depends on. When this passes, the Go
// authoring layer can generate the entire IR, so Python (export_ir + the map /
// spindle / canon_user / routes sources) is redundant for it. Per-section first
// for a legible failure, then the whole document.
func TestBuildIRMatchesCommittedIR(t *testing.T) {
	doc, err := ir.Load()
	if err != nil {
		t.Fatalf("load committed IR: %v", err)
	}
	built := BuildIR()

	canon := func(v pyjson.Value) string {
		s, err := pyjson.Canonical(v)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		return s
	}

	// Every top-level section, individually (legible diffs).
	for _, sec := range built.Keys() {
		want := ir.Get(doc, sec)
		if want == nil {
			t.Errorf("committed IR missing section %q that BuildIR emits", sec)
			continue
		}
		got, _ := built.Get(sec)
		gc, wc := canon(got), canon(want)
		if gc != wc {
			// sections can be large; bound the echo
			max := 1200
			gs, ws := gc, wc
			if len(gs) > max {
				gs = gs[:max] + "…"
			}
			if len(ws) > max {
				ws = ws[:max] + "…"
			}
			t.Errorf("section %q differs from committed IR\n  built: %s\n  want:  %s", sec, gs, ws)
		}
	}

	// No committed section is dropped by BuildIR.
	for _, sec := range doc.Keys() {
		if _, ok := built.Get(sec); !ok {
			t.Errorf("BuildIR() drops committed IR section %q", sec)
		}
	}

	// Whole-document equality (the definitive gate).
	if canon(built) != canon(doc) {
		t.Errorf("BuildIR() != committed ir.json at the document level (see section diffs above)")
	}
}
