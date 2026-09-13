package authoring

import "sort"

// registry is the Go-native equivalent of byakugan.mappings.MAPPINGS: each map
// module registers its entries in an init(). It is UNEXPORTED so callers cannot
// add/replace entries or bypass register()'s duplicate-key guard; read access is
// through Keys()/Lookup(). (Lookup returns the Entry by value; since Entry holds
// slices/pointers that copy is shallow, so callers must treat a returned Entry as
// read-only rather than mutate its fields.) A duplicate key is a programming
// error (mirrors the Python __init__ hard ImportError on collision).
var registry = map[string]Entry{}

func register(key string, e Entry) {
	if _, dup := registry[key]; dup {
		panic("authoring: duplicate map key " + key)
	}
	registry[key] = e
}

// Keys returns the registered map keys in sorted order (export_ir emits the
// mappings section sorted).
func Keys() []string {
	ks := make([]string, 0, len(registry))
	for k := range registry {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Lookup returns the registered entry for key (read-only access to the
// registry).
func Lookup(key string) (Entry, bool) {
	e, ok := registry[key]
	return e, ok
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
