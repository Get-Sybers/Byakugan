// JLECmd (jump lists) → per-entry records — the port of
// byakugan/adapters/jlecmd.py (frozen at tests/parity/reference/jlecmd.py).
package adapt

import (
	"fmt"
	"math"
	"math/big"
	"regexp"

	"github.com/get-sybers/byakugan/go/internal/markers"
	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

var dotnetDateRe = regexp.MustCompile(`/Date\((-?\d+)\)/`)

// DotnetDate is jlecmd.dotnet_date: '/Date(1522187139502)/' (ms since the
// epoch) → an aware-UTC ISO-8601 string; a falsy value → nil; a value with no
// /Date(..)/ in it passes through as str(v); an out-of-range instant → nil
// (Python's `except (ValueError, OverflowError, OSError)`).
func DotnetDate(v pyjson.Value) pyjson.Value {
	if !record.Truthy(v) { // `if not v`
		return nil
	}
	s := record.PyStr(v)
	m := dotnetDateRe.FindStringSubmatch(s)
	if m == nil {
		return s // already rendered — pass through
	}
	ms, ok := new(big.Int).SetString(m[1], 10)
	if !ok {
		return nil
	}
	// Python `ms / 1000.0` converts the int to a double FIRST (OverflowError
	// when it does not fit), then divides — the same two roundings here.
	f, _ := new(big.Float).SetInt(ms).Float64()
	if math.IsInf(f, 0) {
		return nil
	}
	sec, us, ok := markers.FromTimestamp(f / 1000.0)
	if !ok {
		return nil
	}
	return markers.IsoUTC(sec, us)
}

// Jlecmd is jlecmd.flatten: one JLECmd AutomaticDestinations record → one flat
// record per DestListEntry, with the owning application's context merged in.
// A record with no entries yields nothing (an empty jump list asserts no file
// interaction).
func Jlecmd(rec *pyjson.Object) ([]*pyjson.Object, error) {
	if rec == nil {
		return nil, nil
	}
	app := pyjson.NewObject()
	if v, _ := rec.Get("AppId"); record.Truthy(v) { // `record.get("AppId") or {}`
		o, ok := v.(*pyjson.Object)
		if !ok { // Python: app.get(...) → AttributeError
			return nil, fmt.Errorf("jlecmd: AppId is not a JSON object")
		}
		app = o
	}
	appID, _ := app.Get("AppId")
	appDesc, _ := app.Get("Description")
	sourceFile, _ := rec.Get("SourceFile")

	var entries []pyjson.Value
	if v, _ := rec.Get("DestListEntries"); record.Truthy(v) { // `... or []`
		lst, ok := v.([]pyjson.Value)
		if !ok {
			return nil, fmt.Errorf("jlecmd: DestListEntries is not a JSON list")
		}
		entries = lst
	}

	out := make([]*pyjson.Object, 0, len(entries))
	for _, ev := range entries {
		e, ok := ev.(*pyjson.Object) // `if not isinstance(e, dict): continue`
		if !ok {
			continue
		}
		g := func(k string) pyjson.Value { v, _ := e.Get(k); return v }
		flat := pyjson.NewObject()
		flat.Set("Path", g("Path"))
		flat.Set("LastModified", DotnetDate(g("LastModified")))
		flat.Set("CreatedOn", DotnetDate(g("CreatedOn")))
		flat.Set("Hostname", g("Hostname"))
		flat.Set("InteractionCount", g("InteractionCount"))
		flat.Set("EntryNumber", g("EntryNumber"))
		flat.Set("MRUPosition", g("MRUPosition"))
		flat.Set("Pinned", g("Pinned"))
		flat.Set("MacAddress", g("MacAddress"))
		flat.Set("VolumeDroid", g("VolumeDroid"))
		flat.Set("AppId", appID)
		flat.Set("AppDescription", appDesc)
		flat.Set("SourceFile", sourceFile)
		out = append(out, flat)
	}
	return out, nil
}
