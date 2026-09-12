// The container reader half of the l2t splitter — l2t_split
// ._iter_numbered_jsonl's exact text semantics.
package split

import (
	"bufio"
	"os"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// iterNumbered calls fn(1-based physical line number, record) for every JSON
// line of path, and counts EVERY physical line into *lines (blank and
// unparseable lines are skipped but counted — that is what makes RecordId
// stable across a re-split).
//
// `open(path, encoding="utf-8", errors="replace")`: universal newlines, one
// U+FFFD per maximal ill-formed UTF-8 subpart, NO BOM stripping. Per line:
// str.strip(), skip if empty, skip silently if json.loads raises. A container
// that cannot be opened yields nothing (Python's `except OSError: return`).
func iterNumbered(path string, fn func(lineno int, rec pyjson.Value) error, lines *int) error {
	f, err := os.Open(path)
	if err != nil {
		return nil // vanish-tolerant, exactly like the Python reference
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 256*1024*1024)
	sc.Split(scanUniversalLines)
	lineno := 0
	for sc.Scan() {
		lineno++
		if lines != nil {
			*lines = lineno
		}
		s := record.Strip(decodeReplace(sc.Bytes()))
		if s == "" {
			continue
		}
		v, err := pyjson.DecodeString(s)
		if err != nil {
			continue // json.JSONDecodeError / ValueError → skipped
		}
		if err := fn(lineno, v); err != nil {
			return err
		}
	}
	return sc.Err()
}

// scanUniversalLines is a bufio.SplitFunc for Python's universal newlines: a
// line ends at \n, \r\n or a lone \r. Byte-level splitting is safe — 0x0A and
// 0x0D never occur inside a (well- or ill-formed) multi-byte sequence.
//
// Deliberately a private copy of readers' identical helper: readers/ is a
// shared engine file and this package owns its own reader (the two differ in
// everything above the line-splitting layer — see the package doc).
func scanUniversalLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			return i + 1, data[:i], nil
		case '\r':
			if i+1 < len(data) {
				if data[i+1] == '\n' {
					return i + 2, data[:i], nil
				}
				return i + 1, data[:i], nil
			}
			if atEOF {
				return i + 1, data[:i], nil
			}
			return 0, nil, nil // need one more byte to see if \r\n
		}
	}
	if atEOF {
		if len(data) == 0 {
			return 0, nil, nil
		}
		return len(data), data, nil
	}
	return 0, nil, nil
}

// decodeReplace decodes b as UTF-8 with Python errors='replace': every maximal
// subpart of an ill-formed subsequence becomes ONE U+FFFD.
func decodeReplace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
			continue
		}
		n := sequenceLen(b, i)
		if n > 0 {
			sb.Write(b[i : i+n])
			i += n
			continue
		}
		sb.WriteRune(0xFFFD)
		i += -n // -n = length of the maximal (invalid) subpart consumed
	}
	return sb.String()
}

// sequenceLen returns the length of the well-formed sequence at i (>0), or the
// negated length of the maximal subpart to replace (<0, at least -1).
func sequenceLen(b []byte, i int) int {
	c := b[i]
	cont := func(x byte) bool { return x >= 0x80 && x <= 0xBF }
	switch {
	case c < 0xC2: // stray continuation or overlong C0/C1
		return -1
	case c < 0xE0: // 2-byte
		if i+1 < len(b) && cont(b[i+1]) {
			return 2
		}
		return -1
	case c < 0xF0: // 3-byte
		lo, hi := byte(0x80), byte(0xBF)
		if c == 0xE0 {
			lo = 0xA0
		} else if c == 0xED {
			hi = 0x9F // surrogates are ill-formed
		}
		if i+1 >= len(b) || b[i+1] < lo || b[i+1] > hi {
			return -1
		}
		if i+2 >= len(b) || !cont(b[i+2]) {
			return -2
		}
		return 3
	case c < 0xF5: // 4-byte
		lo, hi := byte(0x80), byte(0xBF)
		if c == 0xF0 {
			lo = 0x90
		} else if c == 0xF4 {
			hi = 0x8F
		}
		if i+1 >= len(b) || b[i+1] < lo || b[i+1] > hi {
			return -1
		}
		if i+2 >= len(b) || !cont(b[i+2]) {
			return -2
		}
		if i+3 >= len(b) || !cont(b[i+3]) {
			return -3
		}
		return 4
	default: // F5..FF
		return -1
	}
}
