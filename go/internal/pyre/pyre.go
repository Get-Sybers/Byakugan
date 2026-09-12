// Package pyre adapts the mapping tables' Python-dialect regex patterns to
// Go's RE2 engine with Python re.search semantics (go/DESIGN.md).
//
// RE2 has no lookahead, so the ONE lookahead idiom the tables use — a
// negative lookahead guarding a start-anchored capture — is translated into
// a {deny, accept} pair:
//
//	^(?!X$)(REST)$            deny ^X$    accept ^(REST)$
//	^(?!(?:X)$)(REST)$        deny ^X$    accept ^(REST)$
//	\A(?!(?:X)\Z)(REST)\Z     deny \AX\z  accept \A(REST)\z
//	^(?!PFX)(REST)$           deny ^PFX   accept ^(REST)$   (bare prefix guard)
//
// Because the pattern is start-anchored, re.search can only match at
// position 0, so "the lookahead fails at 0" is exactly "deny matches".
// Every other pattern compiles directly, with two Python-isms rewritten:
// \Z -> \z, and a FINAL unanchored-consuming $ -> (?:\n)?\z (Python's $
// also matches just before one trailing newline; nothing captures past it,
// so consuming the newline is group-equivalent). Everything else is already
// re.search-equal in RE2: leftmost-first submatches, `.` excluding \n,
// inline (?i) (the tables only use it pattern-initial, where Python's
// whole-pattern scope and RE2's from-here scope coincide).
package pyre

import (
	"fmt"
	"regexp"
	"strings"
)

// Regexp is a compiled Python-dialect pattern.
type Regexp struct {
	src    string
	accept *regexp.Regexp
	deny   *regexp.Regexp // non-nil only for the translated lookahead idiom
}

// Compile compiles a Python re pattern for re.search semantics.
func Compile(pattern string) (*Regexp, error) {
	if deny, accept, ok, err := splitNegLookahead(pattern); err != nil {
		return nil, err
	} else if ok {
		d, err := regexp.Compile(deny)
		if err != nil {
			return nil, fmt.Errorf("pyre: deny of %q: %w", pattern, err)
		}
		a, err := regexp.Compile(accept)
		if err != nil {
			return nil, fmt.Errorf("pyre: accept of %q: %w", pattern, err)
		}
		return &Regexp{src: pattern, accept: a, deny: d}, nil
	}
	a, err := regexp.Compile(rewrite(pattern))
	if err != nil {
		return nil, fmt.Errorf("pyre: %q: %w", pattern, err)
	}
	return &Regexp{src: pattern, accept: a}, nil
}

// MustCompile is Compile that panics — for the engine's static tables.
func MustCompile(pattern string) *Regexp {
	r, err := Compile(pattern)
	if err != nil {
		panic(err)
	}
	return r
}

// String returns the original Python pattern.
func (r *Regexp) String() string { return r.src }

// search runs re.search and returns the submatch index vector, or nil.
func (r *Regexp) search(s string) []int {
	if r.deny != nil && r.deny.MatchString(s) {
		return nil
	}
	return r.accept.FindStringSubmatchIndex(s)
}

// Matches reports whether re.search(pattern, s) would find a match.
func (r *Regexp) Matches(s string) bool { return r.search(s) != nil }

// Group1 is the regex1 marker's semantics: m = re.search(...); m and
// m.group(1). ok is false when there is no match, the pattern has no group,
// or group 1 did not participate (Python's m.group(1) is None).
func (r *Regexp) Group1(s string) (string, bool) {
	idx := r.search(s)
	if idx == nil || len(idx) < 4 || idx[2] < 0 {
		return "", false
	}
	return s[idx[2]:idx[3]], true
}

// --- translation ------------------------------------------------------------

// rewrite maps the Python-only escapes/assertions onto RE2:
// \Z -> \z, and a FINAL $ -> (?:\n)?\z. Escapes are respected (\$ and \\Z
// stay literal).
func rewrite(pat string) string {
	var b strings.Builder
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		if c == '\\' && i+1 < len(pat) {
			if pat[i+1] == 'Z' {
				b.WriteString(`\z`)
			} else {
				b.WriteByte(c)
				b.WriteByte(pat[i+1])
			}
			i++
			continue
		}
		if c == '$' && i == len(pat)-1 {
			b.WriteString(`(?:\n)?\z`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// splitNegLookahead recognizes the start-anchored negative-lookahead idiom
// `<^|\A>(?!NEG)REST` and returns the translated (deny, accept) patterns.
// A lookahead anywhere else is an error (never used by the tables; refusing
// is safer than silently mis-matching).
func splitNegLookahead(pat string) (deny, accept string, ok bool, err error) {
	var anchor, rest string
	switch {
	case strings.HasPrefix(pat, "^(?!"):
		anchor, rest = "^", pat[len("^(?!"):]
	case strings.HasPrefix(pat, `\A(?!`):
		anchor, rest = `\A`, pat[len(`\A(?!`):]
	default:
		if i := strings.Index(pat, "(?!"); i >= 0 || strings.Contains(pat, "(?=") ||
			strings.Contains(pat, "(?<") {
			return "", "", false, fmt.Errorf("pyre: unsupported lookaround in %q "+
				"(only the start-anchored ^(?!...) idiom is translated)", pat)
		}
		return "", "", false, nil
	}
	depth := 1
	end := -1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return "", "", false, fmt.Errorf("pyre: unbalanced lookahead in %q", pat)
	}
	neg, tail := rest[:end], rest[end+1:]
	if strings.Contains(neg, "(?!") || strings.Contains(tail, "(?!") {
		return "", "", false, fmt.Errorf("pyre: multiple lookaheads in %q", pat)
	}
	deny = rewrite(anchor + "(?:" + neg + ")")
	// an end-anchor INSIDE the lookahead body anchors the deny; rewrite()
	// already turned a final $ / \Z of the body into the Go equivalent, but
	// the body sits inside (?:...) so handle its OWN trailing anchor here.
	switch {
	case strings.HasSuffix(neg, `\Z`):
		deny = rewrite(anchor+"(?:"+strings.TrimSuffix(neg, `\Z`)+")") + `\z`
	case strings.HasSuffix(neg, "$") && !strings.HasSuffix(neg, `\$`):
		deny = rewrite(anchor+"(?:"+strings.TrimSuffix(neg, "$")+")") + `(?:\n)?\z`
	}
	accept = rewrite(anchor + tail)
	return deny, accept, true, nil
}
