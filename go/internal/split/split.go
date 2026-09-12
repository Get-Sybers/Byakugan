// Package split is the Go port of byakugan/adapters/l2t_split.py (frozen at
// tests/parity/reference/l2t_split.py): a raw log2timeline json_line file is a
// CONTAINER of many parsers, and this splits it — streaming, never slurping —
// into per-parser table files whose rows are the wrapped
// {SourceImage, RecordId, Parser, Record, Timestamp} shape the l2t CAR maps
// consume.
//
// RecordId is the record's 1-based PHYSICAL line in the container: blank and
// unparseable lines are skipped but still counted, so a later fix that makes a
// bad line parse never renumbers its neighbours.
//
// The reader here is deliberately NOT readers.ForEach — l2t_split opens the
// container with encoding="utf-8" (NOT utf-8-sig) and only str.strip()s each
// line: no BOM stripping, no trailing-comma rstrip, no "["/"]" skipping. A
// BOM'd first line therefore fails json.loads and is skipped (but counted), in
// both engines.
package split

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/get-sybers/byakugan/go/internal/markers"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

var nonAlnumRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// TableName is l2t_split.table_name: the top-level parser segment, CamelCased,
// behind an "L2t" prefix — filestat → L2tFilestat, winreg/appcompatcache →
// L2tWinreg, firefox_cache → L2tFirefoxCache.
func TableName(parser string) string {
	if parser == "" {
		parser = "unknown"
	}
	top := parser
	if i := strings.Index(top, "/"); i >= 0 {
		top = top[:i]
	}
	if top == "" {
		top = "unknown"
	}
	var parts []string
	for _, p := range nonAlnumRe.Split(top, -1) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "L2tUnknown"
	}
	var b strings.Builder
	b.WriteString("L2t")
	for _, p := range parts {
		c := p[0] // parts are ASCII [A-Za-z0-9]+ — str.upper() is ASCII here
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b.WriteByte(c)
		b.WriteString(p[1:])
	}
	return b.String()
}

// Row is l2t_split._l2t_row: (table, wrapped-JSONL-string) for one Plaso
// record. recordID < 0 means "the caller has none" (Python's `record_id=None`),
// and the RecordId key is left out. A zero/absent/out-of-range timestamp
// leaves Timestamp unset (never 1970).
func Row(rec pyjson.Value, sourceRel string, recordID int) (string, string, error) {
	o, ok := rec.(*pyjson.Object)
	if !ok {
		// Python: rec.get(...) → AttributeError. The live lane only ever
		// carries objects; fail loudly rather than diverge silently.
		return "", "", fmt.Errorf("split: record is not a JSON object")
	}
	parser := "unknown"
	if v, _ := o.Get("parser"); record.Truthy(v) { // `rec.get("parser") or "unknown"`
		parser = record.PyStr(v)
	}
	row := pyjson.NewObject()
	row.Set("SourceImage", sourceRel)
	if recordID >= 0 {
		row.Set("RecordId", pyjson.Int(int64(recordID)))
	}
	row.Set("Parser", parser)
	row.Set("Record", o)
	if ts, _ := o.Get("timestamp"); isNumber(ts) && positive(ts) {
		if f, ok := record.PyFloat(ts); ok {
			// datetime.fromtimestamp(ts / 1_000_000, utc)
			//     .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
			if sec, us, ok := markers.FromTimestamp(f / 1e6); ok {
				row.Set("Timestamp", strftimeUTC(sec, us))
			}
		}
	}
	line, err := pyjson.Dumps(row)
	if err != nil {
		return "", "", err
	}
	return TableName(parser), line, nil
}

// isNumber is Python `isinstance(ts, (int, float))` — bool IS an int there.
func isNumber(v pyjson.Value) bool {
	switch v.(type) {
	case bool, *big.Int, float64:
		return true
	}
	return false
}

// positive is `ts > 0` for the numeric types isNumber admits.
func positive(v pyjson.Value) bool {
	switch x := v.(type) {
	case bool:
		return x // True > 0, False == 0
	case *big.Int:
		return x.Sign() > 0
	case float64:
		return x > 0 // NaN is not > 0, matching Python
	}
	return false
}

// strftimeUTC renders (epoch sec, µs) as strftime("%Y-%m-%dT%H:%M:%S.%fZ") —
// %f is ALWAYS six digits (unlike isoformat, which drops a zero fraction).
func strftimeUTC(sec int64, us int) string {
	t := time.Unix(sec, 0).UTC()
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
		t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second(), us)
}

// Table is one output table of a split, in the order its first record appeared.
type Table struct {
	Name string
	Path string
}

// Result is what SplitL2t produced: the per-table files (in first-seen order)
// and the number of PHYSICAL lines read from the container.
type Result struct {
	Tables []Table
	Lines  int
}

// SplitL2t streams a Plaso json_line file into per-parser table files under
// outDir, each named "<prefix>.<table>" — l2t_split.split_l2t. Nothing but one
// record and a handful of file handles is live at a time.
//
// A container that cannot be opened yields an empty result and no error
// (l2t_split's vanish-tolerant `except OSError: return`); callers that want a
// missing input to be fatal check for it themselves.
func SplitL2t(path, sourceRel, outDir, prefix string) (*Result, error) {
	res := &Result{}
	handles := map[string]*os.File{}
	closed := false
	defer func() {
		if closed {
			return
		}
		for _, fh := range handles {
			fh.Close()
		}
	}()
	err := iterNumbered(path, func(lineno int, rec pyjson.Value) error {
		table, line, err := Row(rec, sourceRel, lineno)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineno, err)
		}
		fh, ok := handles[table]
		if !ok {
			fp := filepath.Join(outDir, prefix+"."+table)
			fh, err = os.Create(fp)
			if err != nil {
				return err
			}
			handles[table] = fh
			res.Tables = append(res.Tables, Table{Name: table, Path: fp})
		}
		if _, err := fh.WriteString(line); err != nil {
			return err
		}
		if _, err := fh.WriteString("\n"); err != nil {
			return err
		}
		return nil
	}, &res.Lines)
	if err != nil {
		return nil, err
	}
	for _, fh := range handles {
		if err := fh.Close(); err != nil {
			return nil, err
		}
	}
	closed = true
	return res, nil
}

// Tables is l2t_split.l2t_tables: a streaming dry-run scan → {table: count},
// in first-seen order.
func Tables(path string) ([]Table, map[string]int, error) {
	var order []Table
	counts := map[string]int{}
	lines := 0
	err := iterNumbered(path, func(_ int, rec pyjson.Value) error {
		table, _, err := Row(rec, "", -1)
		if err != nil {
			return err
		}
		if _, ok := counts[table]; !ok {
			order = append(order, Table{Name: table})
		}
		counts[table]++
		return nil
	}, &lines)
	if err != nil {
		return nil, nil, err
	}
	return order, counts, nil
}
