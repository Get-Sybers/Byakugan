// Package predicates holds the hand-ported variant gate functions, registered
// by name in per-family files (predicates_<family>.go, one per Python mapping
// module) so no shared file is edited as families are ported.
//
// Stage B ships the exemplar families (mappings/core.py, mappings/zeek_conn.py);
// stage C fills the rest. Check() reports IR predicate names with no Go
// registration — the Go tests and `byakugan-parse ir-check` surface the gap
// without failing the build while porting is in flight.
package predicates

import (
	"fmt"
	"sort"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/record"
)

// Func is one variant gate: record in, claim/decline out. A predicate MAY
// mutate the record (zeek_conn_has_state stamps its _zc_ derivations) — it
// runs before the map resolves, exactly like Python's evaluation order.
type Func func(*record.Record) bool

var registry = map[string]Func{}

// Register binds a predicate name to its Go port. Called from init() in the
// per-family files; a duplicate registration is a programming error.
func Register(name string, fn Func) {
	if _, dup := registry[name]; dup {
		panic("predicates: duplicate registration of " + name)
	}
	registry[name] = fn
}

// Lookup returns the registered predicate for name.
func Lookup(name string) (Func, bool) {
	fn, ok := registry[name]
	return fn, ok
}

// Registered returns the registered names, sorted.
func Registered() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Missing returns the IR predicate names that have no Go registration yet.
func Missing(irNames []string) []string {
	var out []string
	for _, n := range irNames {
		if _, ok := registry[n]; !ok {
			out = append(out, n)
		}
	}
	return out
}

// Check errors when any IR predicate name has no Go registration — the
// completeness gate that must pass once every family is ported (stage C).
func Check(irNames []string) error {
	if m := Missing(irNames); len(m) > 0 {
		return fmt.Errorf("predicates: %d IR predicate(s) not registered in Go: %s",
			len(m), strings.Join(m, ", "))
	}
	return nil
}
