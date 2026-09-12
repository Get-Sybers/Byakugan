// Package ir loads the embedded intermediate representation — the JSON
// snapshot of the live Python parse tables that `python -m byakugan.export_ir`
// serializes to ir.json (the committed file this package embeds). The IR is
// the single source of truth the Go engine parses from; `--check` in CI holds
// it in step with the Python tables.
//
// Stage A exposes the raw pyjson document plus path navigation and a
// structural validation; the resolver walks the decoded pyjson values directly.
package ir

import (
	_ "embed"
	"fmt"
	"math/big"
	"sync"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
)

//go:embed ir.json
var raw []byte

// Version is the IR document version this engine understands.
const Version = 1

// Raw returns the embedded ir.json bytes (for `byakugan-parse ir-check`).
func Raw() []byte { return raw }

var (
	loadOnce sync.Once
	loadDoc  *pyjson.Object
	loadErr  error
)

// Load decodes (once) and validates the embedded IR.
func Load() (*pyjson.Object, error) {
	loadOnce.Do(func() {
		v, err := pyjson.Decode(raw)
		if err != nil {
			loadErr = fmt.Errorf("ir: %w", err)
			return
		}
		doc, ok := v.(*pyjson.Object)
		if !ok {
			loadErr = fmt.Errorf("ir: document is not an object")
			return
		}
		if err := validate(doc); err != nil {
			loadErr = err
			return
		}
		loadDoc = doc
	})
	return loadDoc, loadErr
}

// validate checks the structural contract stage A depends on.
func validate(doc *pyjson.Object) error {
	ver, ok := doc.Get("ir_version")
	if !ok {
		return fmt.Errorf("ir: no ir_version")
	}
	n, ok := ver.(*big.Int)
	if !ok || n.Int64() != Version {
		return fmt.Errorf("ir: ir_version %v, engine understands %d", ver, Version)
	}
	for _, k := range []string{"marker_kinds", "mappings", "routes", "evtx_maps",
		"adapters", "spindle", "canon_user", "predicate_names", "golden"} {
		if _, ok := doc.Get(k); !ok {
			return fmt.Errorf("ir: missing top-level section %q", k)
		}
	}
	return nil
}

// Get navigates the document by object keys; nil when any hop is missing.
func Get(v pyjson.Value, path ...string) pyjson.Value {
	for _, k := range path {
		o, ok := v.(*pyjson.Object)
		if !ok {
			return nil
		}
		v, ok = o.Get(k)
		if !ok {
			return nil
		}
	}
	return v
}
