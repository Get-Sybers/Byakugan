package ir

import (
	"math/big"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

// TestLoad validates the embedded IR and its stage-A structural contract.
func TestLoad(t *testing.T) {
	doc, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	maps, ok := Get(doc, "mappings").(*pyjson.Object)
	if !ok || maps.Len() == 0 {
		t.Fatal("ir: no mappings")
	}
	routes, ok := Get(doc, "routes").([]pyjson.Value)
	if !ok || len(routes) == 0 {
		t.Fatal("ir: no routes")
	}
	// every routed key resolves to a mapping entry or a declared adapter key
	// (l2t_winevt fans through the evtx maps; pipeline._consume)
	adapters, _ := Get(doc, "adapters").(*pyjson.Object)
	for _, rv := range routes {
		pair := rv.([]pyjson.Value)
		for _, kv := range pair[1].([]pyjson.Value) {
			key := kv.(string)
			if _, ok := maps.Get(key); ok {
				continue
			}
			if adapters != nil {
				if _, ok := adapters.Get(key); ok {
					continue
				}
			}
			t.Errorf("route %v names unmapped artefact %q", pair[0], key)
		}
	}
	// every adapter fan-out target is a mapping
	if adapters != nil {
		for _, name := range adapters.Keys() {
			for _, mv := range Get(adapters, name, "maps").([]pyjson.Value) {
				if _, ok := maps.Get(mv.(string)); !ok {
					t.Errorf("adapter %q fans to unmapped artefact %q", name, mv)
				}
			}
		}
	}
	// every variant predicate name is declared in predicate_names
	predsV, _ := Get(doc, "predicate_names").([]pyjson.Value)
	preds := map[string]bool{}
	for _, p := range predsV {
		preds[p.(string)] = true
	}
	if len(preds) == 0 {
		t.Fatal("ir: no predicate_names")
	}
	for _, key := range maps.Keys() {
		entryV, _ := maps.Get(key)
		entry := entryV.(*pyjson.Object)
		variantsV, ok := entry.Get("variants")
		if !ok {
			continue // a variant-less entry is its own leaf
		}
		for _, vv := range variantsV.([]pyjson.Value) {
			pair := vv.([]pyjson.Value)
			if name := pair[0].(string); !preds[name] {
				t.Errorf("mapping %q variant predicate %q not in predicate_names", key, name)
			}
		}
	}
	// spindle registry: positional + identities present
	pos := Get(doc, "spindle", "positional", "fields")
	if fields, ok := pos.([]pyjson.Value); !ok || len(fields) == 0 {
		t.Fatal("ir: no spindle positional fields")
	}
	if v, ok := Get(doc, "spindle", "positional", "version").(*big.Int); !ok || v.Sign() < 1 {
		t.Fatal("ir: bad spindle positional version")
	}
	idents, ok := Get(doc, "spindle", "identities").(*pyjson.Object)
	if !ok || idents.Len() == 0 {
		t.Fatal("ir: no spindle identities")
	}
	// the frozen wire constant rides in the IR too — belt and braces
	url, _ := Get(doc, "spindle", "namespace", "CAR_NS_URL").(string)
	if url != "https://github.com/Get-Sybers/PIIAT-MitreCar/stix" {
		t.Fatalf("ir: CAR_NS_URL drifted: %q", url)
	}
}
