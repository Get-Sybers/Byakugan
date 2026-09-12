// Package readers is the Go side of byakugan/readers.py iter_jsonl — line
// streaming with CPython's exact text semantics:
//
//   - utf-8-sig: one leading BOM (EF BB BF) stripped;
//   - errors='replace': each maximal subpart of an ill-formed UTF-8 sequence
//     becomes ONE U+FFFD (the CPython/Unicode substitution rule);
//   - universal newlines: \n, \r\n and \r all end a line;
//   - per line: str.strip() (Unicode whitespace), rstrip(",") (every trailing
//     comma), skip blank / "[" / "]" lines, skip undecodable-JSON lines
//     silently.
//
// tests/parity/gen_reader_vectors.py records the Python behavior on crafted
// byte inputs; readers_test.go replays it.
package readers

import (
	"bufio"
	"os"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// ForEach streams every JSON record of path through fn, in input order.
// fn's error aborts the stream and is returned.
func ForEach(path string, fn func(pyjson.Value) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 256*1024*1024)
	sc.Split(scanUniversalLines)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if first {
			first = false
			if len(line) >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF {
				line = line[3:] // utf-8-sig: strip ONE leading BOM
			}
		}
		s := decodeReplace(line)
		s = strings.TrimRight(record.Strip(s), ",")
		if s == "" || s == "[" || s == "]" {
			continue
		}
		v, err := pyjson.DecodeString(s)
		if err != nil {
			continue // json.JSONDecodeError → skip silently
		}
		if err := fn(v); err != nil {
			return err
		}
	}
	return sc.Err()
}

// scanUniversalLines is a bufio.SplitFunc for Python's universal newlines:
// a line ends at \n, \r\n or a lone \r. Byte-level splitting is safe — 0x0A
// and 0x0D never appear inside a (well- or ill-formed) multi-byte sequence.
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

// decodeReplace decodes b as UTF-8 with Python errors='replace': every
// maximal subpart of an ill-formed subsequence is replaced by ONE U+FFFD.
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

// sequenceLen returns the length of the well-formed sequence at i (>0), or
// the negated length of the maximal subpart to replace (<0, at least -1).
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
