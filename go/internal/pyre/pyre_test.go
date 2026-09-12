package pyre

import (
	"os"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// TestVectors replays every recorded Python re.search verdict —
// tests/parity/gen_pyre_vectors.py walks the LIVE mapping tables for the
// battery, so a new mapping pattern lands here on regeneration.
func TestVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	doc, err := pyjson.Decode(data)
	if err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	root, _ := doc.(*pyjson.Object)
	if root == nil {
		t.Fatal("vectors: not an object")
	}
	listV, _ := root.Get("vectors")
	list, _ := listV.([]pyjson.Value)
	if len(list) == 0 {
		t.Fatal("no vectors")
	}
	patterns, cases, lookaheads := 0, 0, 0
	for _, pv := range list {
		rec := pv.(*pyjson.Object)
		patV, _ := rec.Get("pattern")
		pattern := patV.(string)
		re, err := Compile(pattern)
		if err != nil {
			t.Errorf("Compile(%q): %v", pattern, err)
			continue
		}
		if re.deny != nil {
			lookaheads++
		}
		patterns++
		casesV, _ := rec.Get("cases")
		for _, cv := range casesV.([]pyjson.Value) {
			c := cv.(*pyjson.Object)
			inV, _ := c.Get("in")
			in := inV.(string)
			wantMatchedV, _ := c.Get("matched")
			wantMatched := wantMatchedV.(bool)
			wantG1, _ := c.Get("group1") // string or nil
			cases++
			if got := re.Matches(in); got != wantMatched {
				t.Errorf("%q .search(%q): matched=%v, want %v", pattern, in, got, wantMatched)
				continue
			}
			g1, ok := re.Group1(in)
			if wantG1 == nil {
				if ok {
					t.Errorf("%q .group1(%q) = %q, want None", pattern, in, g1)
				}
			} else if !ok || g1 != wantG1.(string) {
				t.Errorf("%q .group1(%q) = %q (%v), want %q", pattern, in, g1, ok, wantG1)
			}
		}
	}
	if lookaheads < 6 {
		t.Errorf("only %d negative-lookahead patterns exercised; the tables carry 6", lookaheads)
	}
	t.Logf("%d patterns (%d lookahead-translated), %d cases", patterns, lookaheads, cases)
}

// TestNegLookaheadTranslation pins the three translated idioms structurally.
func TestNegLookaheadTranslation(t *testing.T) {
	for _, pat := range []string{
		`^(?!LOCAL$)(.+)$`,
		`\A(?!(?:0\.0\.0\.0|127\.0\.0\.1|::1)\Z)(.+)\Z`,
		`^(?!UEME_)(.+)$`,
		`^(?!(?:::1|127\.0\.0\.1|LOCAL)$)(.+)$`,
		`^(?!0$)(\d+)$`,
		`^(?!S-1-0-0$)(S-.+)$`,
	} {
		re, err := Compile(pat)
		if err != nil {
			t.Errorf("Compile(%q): %v", pat, err)
			continue
		}
		if re.deny == nil {
			t.Errorf("Compile(%q): idiom not recognized (no deny half)", pat)
		}
	}
}

// TestUnsupportedLookaround pins the refusal: anything but the start-anchored
// negative-lookahead idiom must fail to compile, never silently mis-match.
func TestUnsupportedLookaround(t *testing.T) {
	for _, pat := range []string{
		`x(?!y)`, `(?=x)`, `(?<=x)y`, `(?<!x)y`, `^(?!a$)(?!b$)(.+)$`,
	} {
		if _, err := Compile(pat); err == nil {
			t.Errorf("Compile(%q): expected error", pat)
		}
	}
}
