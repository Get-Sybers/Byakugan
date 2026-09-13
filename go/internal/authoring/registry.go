package authoring

import "sort"

// Registry is the Go-native equivalent of byakugan.mappings.MAPPINGS: each map
// module registers its entries in an init(). A duplicate key is a programming
// error (mirrors the Python __init__ hard ImportError on collision).
var Registry = map[string]Entry{}

func register(key string, e Entry) {
	if _, dup := Registry[key]; dup {
		panic("authoring: duplicate map key " + key)
	}
	Registry[key] = e
}

// Keys returns the registered map keys in sorted order (export_ir emits the
// mappings section sorted).
func Keys() []string {
	ks := make([]string, 0, len(Registry))
	for k := range Registry {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
