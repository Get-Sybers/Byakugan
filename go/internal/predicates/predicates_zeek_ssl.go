// The byakugan/mappings/zeek_ssl.py gate — zeek_ssl_is_tls.
//
// An ssl.log row is CAR-worthy once it identifies the TLS connection it
// observed — a `uid` (the flow it IS) or the requested `server_name` (the SNI).
// Python:
//
//	return bool(rec.get("uid") or rec.get("server_name"))
//
// Python's `or` yields the first truthy operand else the LAST operand, and
// bool() then collapses it — so the whole expression is exactly
// truthy(uid) || truthy(server_name).
package predicates

import (
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("zeek_ssl_is_tls", zsslIsTLS)
}

func zsslIsTLS(r *record.Record) bool {
	return record.Truthy(r.Get("uid")) || record.Truthy(r.Get("server_name"))
}
