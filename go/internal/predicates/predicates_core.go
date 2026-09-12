// Variant predicates of byakugan/mappings/core.py — the evtx_security and
// zeek_http families, ported clause by clause.
package predicates

import (
	"math/big"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("is_sec_4624", func(r *record.Record) bool { return isSec(r, 4624) })
	Register("is_sec_4625", func(r *record.Record) bool { return isSec(r, 4625) })
	Register("is_sec_4672", func(r *record.Record) bool { return isSec(r, 4672) })
	Register("is_http_origin", func(r *record.Record) bool {
		m := strings.ToUpper(getStr(r, "method"))
		return m == "GET" || m == "POST" || m == "PUT"
	})
	Register("is_http_tunnel", func(r *record.Record) bool {
		return strings.ToUpper(getStr(r, "method")) == "CONNECT"
	})
}

// isSec is `rec.get("EventId") == <id> and "Security" in str(rec.get("Channel", ""))`.
func isSec(r *record.Record, id int64) bool {
	return numEq(r.Get("EventId"), id) &&
		strings.Contains(getStr(r, "Channel"), "Security")
}

// getStr is str(rec.get(key, "")): "" when the key is absent, Python str()
// of the value when present (None → "None", like Python).
func getStr(r *record.Record, key string) string {
	if !r.Has(key) {
		return ""
	}
	return record.PyStr(r.Get(key))
}

// numEq is Python `v == <int literal>`: exact for int, numeric for float,
// True/False count as 1/0; strings never equal an int.
func numEq(v pyjson.Value, id int64) bool {
	switch x := v.(type) {
	case *big.Int:
		return x.IsInt64() && x.Int64() == id
	case float64:
		return x == float64(id)
	case bool:
		n := int64(0)
		if x {
			n = 1
		}
		return n == id
	default:
		return false
	}
}
