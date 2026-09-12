// Package markers interprets the 24 marker kinds of the IR against a record —
// the Go side of byakugan/normalize.py _resolve, ported clause by clause.
// A spec is a plain field-name string or {"!": ["kind", arg...]} (the
// export_ir encoding); sources recurse. tests/parity/gen_marker_vectors.py
// records the Python resolver's outputs; markers_test.go replays them.
package markers

import (
	"fmt"
	"strings"
	"sync"

	"github.com/get-sybers/byakugan/go/internal/ir"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/pyre"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// MarkerKey is export_ir.MARKER_KEY — the marker envelope's single key.
const MarkerKey = "!"

var (
	reMu    sync.Mutex
	reCache = map[string]*pyre.Regexp{}
)

func compileCached(pattern string) (*pyre.Regexp, error) {
	reMu.Lock()
	defer reMu.Unlock()
	if r, ok := reCache[pattern]; ok {
		return r, nil
	}
	r, err := pyre.Compile(pattern)
	if err != nil {
		return nil, err
	}
	reCache[pattern] = r
	return r, nil
}

// Resolve resolves a plain field name or a (nestable) marker against a
// record — normalize._resolve.
func Resolve(spec pyjson.Value, rec *record.Record) (pyjson.Value, error) {
	if s, ok := spec.(string); ok {
		return rec.Get(s), nil
	}
	o, ok := spec.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("markers: not a source spec: %T", spec)
	}
	mv, ok := o.Get(MarkerKey)
	if !ok || o.Len() != 1 {
		return nil, fmt.Errorf("markers: object spec without %q envelope", MarkerKey)
	}
	arr, ok := mv.([]pyjson.Value)
	if !ok || len(arr) == 0 {
		return nil, fmt.Errorf("markers: malformed marker envelope")
	}
	kind, ok := arr[0].(string)
	if !ok {
		return nil, fmt.Errorf("markers: marker kind is not a string")
	}
	args := arr[1:]

	switch kind {
	case "first":
		for _, src := range args {
			v, err := Resolve(src, rec)
			if err != nil {
				return nil, err
			}
			if !record.Blank(v) {
				return v, nil
			}
		}
		return nil, nil

	case "const":
		return arg(args, 0), nil

	case "basename":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		return basenameOf(v), nil

	case "ext":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		base := ""
		if b := basenameOf(v); b != nil {
			base = b.(string)
		}
		_, e := ntSplitExt(base)
		e = strings.ToLower(strings.TrimLeft(e, "."))
		if e == "" {
			return nil, nil
		}
		return e, nil

	case "lower":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		return strings.ToLower(record.PyStr(v)), nil

	case "regex1":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		pattern, _ := arg(args, 1).(string)
		re, err := compileCached(pattern)
		if err != nil {
			return nil, err
		}
		if g, ok := re.Group1(record.PyStr(v)); ok {
			return g, nil
		}
		return nil, nil

	case "domain_of":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		s := record.PyStr(v)
		if i := strings.Index(s, "@"); i >= 0 {
			s = s[i+1:]
		}
		if i := strings.Index(s, "/"); i >= 0 { // strip any URL path
			s = s[:i]
		}
		s = strings.ToLower(s)
		if s == "" {
			return nil, nil
		}
		return s, nil

	case "concat":
		var out strings.Builder
		for _, part := range args {
			v, err := Resolve(part, rec)
			if err != nil {
				return nil, err
			}
			if record.Blank(v) {
				return nil, nil
			}
			out.WriteString(record.PyStr(v))
		}
		return out.String(), nil

	case "payload":
		field, _ := arg(args, 0).(string)
		key, _ := arg(args, 1).(string)
		names, hasNames, data := rec.ParsedPayload(field)
		if hasNames { // EventData.Data indexed by @Name
			v, _ := names.Get(key)
			return v, nil
		}
		if o, ok := data.(*pyjson.Object); ok { // flat dict (e.g. the wrapped Record)
			v, _ := o.Get(key)
			if s, ok := v.(string); ok {
				v = record.Strip(s)
			}
			if record.Blank(v) {
				return nil, nil
			}
			return v, nil
		}
		return nil, nil

	case "userdata":
		field, _ := arg(args, 0).(string)
		key, _ := arg(args, 1).(string)
		_, _, data := rec.ParsedPayload(field)
		do, ok := data.(*pyjson.Object)
		if !ok {
			return nil, nil
		}
		ud, _ := do.Get("UserData")
		udo, ok := ud.(*pyjson.Object)
		if !ok {
			return nil, nil
		}
		for _, ck := range udo.Keys() { // the single nested element
			child, _ := udo.Get(ck)
			co, ok := child.(*pyjson.Object)
			if !ok {
				continue
			}
			if v, ok := co.Get(key); ok {
				if s, ok := v.(string); ok {
					v = record.Strip(s)
				}
				if record.Blank(v) {
					return nil, nil
				}
				return v, nil
			}
		}
		return nil, nil

	case "host_label":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		s := record.PyStr(v)
		if i := strings.Index(s, "."); i >= 0 {
			s = s[:i]
		}
		if s == "" {
			return nil, nil
		}
		return s, nil

	case "epoch_ts":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		return EpochTs(v), nil

	case "exe_path":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		return exePath(record.PyStr(v)), nil

	case "map_value":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		table, ok := arg(args, 1).(*pyjson.Object)
		if !ok {
			return nil, fmt.Errorf("markers: map_value table is not an object")
		}
		s := record.PyStr(v)
		if b, _ := arg(args, 2).(bool); b {
			s = strings.ToUpper(s)
		}
		tv, _ := table.Get(s) // miss → nil
		return tv, nil

	case "unescape_backslashes":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		return strings.ReplaceAll(record.PyStr(v), `\\`, `\`), nil

	case "replace":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		old, _ := arg(args, 1).(string)
		newer, _ := arg(args, 2).(string)
		return strings.ReplaceAll(record.PyStr(v), old, newer), nil

	case "at":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		idx, ok := intArg(arg(args, 1))
		if !ok {
			return nil, fmt.Errorf("markers: at index is not an int")
		}
		lst, ok := v.([]pyjson.Value)
		if !ok || idx < -len(lst) || idx >= len(lst) {
			return nil, nil
		}
		if idx < 0 {
			idx += len(lst)
		}
		e := lst[idx]
		if s, ok := e.(string); ok {
			e = record.Strip(s)
		}
		if record.Blank(e) {
			return nil, nil
		}
		return e, nil

	case "hex_int":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		if n, ok := record.PyInt(v); ok {
			return n, nil
		}
		if n, ok := record.PyIntParse(record.PyStr(v), 16); ok {
			return n, nil
		}
		return nil, nil

	case "ts_before":
		av, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		bv, err := Resolve(arg(args, 1), rec)
		if err != nil {
			return nil, err
		}
		aSec, aUs, aOK := ParseTs(av)
		bSec, bUs, bOK := ParseTs(bv)
		if !aOK || !bOK {
			return nil, nil
		}
		return aSec < bSec || (aSec == bSec && aUs < bUs), nil

	case "win_program_path":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		s := record.PyStr(v)
		if strings.Contains(s, "\t") { // a UWP package descriptor is not a path
			return nil, nil
		}
		return s, nil

	case "win_program_name":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		if record.Blank(v) {
			return nil, nil
		}
		s := record.PyStr(v)
		if strings.Contains(s, "\t") {
			return pkgFamily(s), nil
		}
		return basenameOf(s), nil

	case "user_canon":
		v, err := Resolve(arg(args, 0), rec)
		if err != nil {
			return nil, err
		}
		return CanonUser(v)

	default:
		return nil, fmt.Errorf("markers: unknown source marker kind %q", kind)
	}
}

// arg returns args[i] or nil.
func arg(args []pyjson.Value, i int) pyjson.Value {
	if i < len(args) {
		return args[i]
	}
	return nil
}

func intArg(v pyjson.Value) (int, bool) {
	n, ok := record.PyInt(v)
	if !ok || !n.IsInt64() {
		return 0, false
	}
	return int(n.Int64()), true
}

// --- path helpers (ntpath / posixpath ports) --------------------------------

// basenameOf is normalize._basename: nil for a blank; ntpath.basename when
// the string contains a backslash, else posixpath.basename; "" → nil.
func basenameOf(v pyjson.Value) pyjson.Value {
	if record.Blank(v) {
		return nil
	}
	s := record.PyStr(v)
	var b string
	if strings.Contains(s, `\`) {
		b = ntBasename(s)
	} else {
		i := strings.LastIndexByte(s, '/')
		b = s[i+1:]
	}
	if b == "" {
		return nil
	}
	return b
}

// ntBasename is ntpath.basename: split off the drive/UNC prefix, then the
// tail after the last \ or /.
func ntBasename(s string) string {
	_, rest := ntSplitDrive(s)
	i := strings.LastIndexAny(rest, `\/`)
	return rest[i+1:]
}

// ntSplitDrive is ntpath.splitdrive (Python 3.10): drive letter or UNC
// \\server\share prefix.
func ntSplitDrive(p string) (drive, rest string) {
	if len(p) >= 2 {
		normp := strings.ReplaceAll(p, "/", `\`)
		if strings.HasPrefix(normp, `\\`) && !strings.HasPrefix(normp[2:], `\`) {
			index := strings.Index(normp[2:], `\`)
			if index == -1 {
				return "", p
			}
			index += 2
			index2 := strings.Index(normp[index+1:], `\`)
			if index2 == 0 {
				return "", p
			}
			if index2 == -1 {
				index2 = len(p)
			} else {
				index2 += index + 1
			}
			return p[:index2], p[index2:]
		}
		if p[1] == ':' {
			return p[:2], p[2:]
		}
	}
	return "", p
}

// ntSplitExt is ntpath.splitext over a (possibly sep-carrying) string:
// leading dots of the last path component never start an extension.
func ntSplitExt(p string) (root, ext string) {
	sepIndex := strings.LastIndexAny(p, `\/`)
	dotIndex := strings.LastIndexByte(p, '.')
	if dotIndex > sepIndex {
		filenameIndex := sepIndex + 1
		for filenameIndex < dotIndex {
			if p[filenameIndex] != '.' {
				return p[:dotIndex], p[dotIndex:]
			}
			filenameIndex++
		}
	}
	return p, ""
}

// exePath is the exe_path marker's body over str(v).
func exePath(s string) string {
	s2 := record.Strip(s)
	if strings.HasPrefix(s2, `"`) {
		end := strings.Index(s2[1:], `"`)
		if end >= 0 {
			end++ // s2.find('"', 1)
		}
		if end > 0 {
			return s2[1:end]
		}
		return strings.Trim(s2, `"`)
	}
	if i := strings.Index(strings.ToLower(s2), ".exe"); i >= 0 {
		return s2[:i+4]
	}
	if i := strings.IndexByte(s2, ' '); i >= 0 {
		return s2[:i]
	}
	return s2
}

// pkgFamily is normalize._pkg_family — the Package Family Name out of a
// TAB-delimited Store/UWP descriptor, or nil.
func pkgFamily(s string) pyjson.Value {
	var parts []string
	for _, p := range strings.Split(s, "\t") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) >= 6 && strings.Contains(parts[4], ".") {
		return parts[4] + "_" + parts[5]
	}
	return nil
}

// --- Windows principal canonicalization (normalize._canon_user) -------------

var (
	canonOnce    sync.Once
	canonErr     error
	sidTable     *pyjson.Object
	nameTable    *pyjson.Object
	authoritySet map[string]bool
)

func loadCanon() error {
	canonOnce.Do(func() {
		doc, err := ir.Load()
		if err != nil {
			canonErr = err
			return
		}
		var ok bool
		sidTable, ok = ir.Get(doc, "canon_user", "wellknown_sids").(*pyjson.Object)
		if !ok {
			canonErr = fmt.Errorf("markers: IR canon_user.wellknown_sids missing")
			return
		}
		nameTable, ok = ir.Get(doc, "canon_user", "wellknown_names").(*pyjson.Object)
		if !ok {
			canonErr = fmt.Errorf("markers: IR canon_user.wellknown_names missing")
			return
		}
		auth, ok := ir.Get(doc, "canon_user", "wellknown_authorities").([]pyjson.Value)
		if !ok {
			canonErr = fmt.Errorf("markers: IR canon_user.wellknown_authorities missing")
			return
		}
		authoritySet = map[string]bool{}
		for _, a := range auth {
			if s, ok := a.(string); ok {
				authoritySet[s] = true
			}
		}
	})
	return canonErr
}

// CanonUser is normalize._canon_user — nil for a blank; a well-known SID →
// its name; a well-known authority prefix stripped; a real domain kept; a
// bare name folded through the well-known-names table.
func CanonUser(v pyjson.Value) (pyjson.Value, error) {
	if err := loadCanon(); err != nil {
		return nil, err
	}
	if record.Blank(v) {
		return nil, nil
	}
	s := record.Strip(record.PyStr(v))
	if s == "" {
		return nil, nil
	}
	if name, ok := sidTable.Get(strings.ToUpper(s)); ok && record.Truthy(name) {
		return name, nil // a well-known SID → its name
	}
	if strings.Contains(s, `\`) {
		dom, acct, _ := strings.Cut(s, `\`)
		if authoritySet[strings.ToUpper(record.Strip(dom))] {
			return canonName(acct), nil // a well-known authority → strip it
		}
		return s, nil // a real machine/AD domain → keep DOMAIN\name
	}
	return canonName(s), nil
}

// canonName is normalize._canon_name.
func canonName(s string) pyjson.Value {
	if v, ok := nameTable.Get(strings.ToUpper(record.Strip(s))); ok {
		return v
	}
	return s
}
