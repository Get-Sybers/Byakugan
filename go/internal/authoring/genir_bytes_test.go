package authoring

import (
	"testing"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// gen-ir must reproduce the committed ir.json BYTE-FOR-BYTE (indent=1,
// ensure_ascii=False, trailing newline) so regenerating from Go leaves the file
// unchanged. This is the phase-4 flip gate: Go owns ir.json generation.
func TestBuildIRSerializesToCommittedBytes(t *testing.T) {
	s, err := pyjson.DumpsIndent(BuildIR(), 1)
	if err != nil {
		t.Fatalf("DumpsIndent: %v", err)
	}
	got := s + "\n"
	want := string(ir.Raw())
	if got == want {
		return
	}
	// locate first divergence
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	i := 0
	for i < n && got[i] == want[i] {
		i++
	}
	lo := i - 60
	if lo < 0 {
		lo = 0
	}
	t.Fatalf("gen-ir bytes != committed ir.json (len got=%d want=%d, first diff at %d)\n  got:  …%q\n  want: …%q",
		len(got), len(want), i, safeSlice(got, lo, i+60), safeSlice(want, lo, i+60))
}

func safeSlice(s string, a, b int) string {
	if a < 0 {
		a = 0
	}
	if b > len(s) {
		b = len(s)
	}
	return s[a:b]
}
