// The byakugan/mappings/zeek_dns.py gate — zeek_dns_is_query.
//
// A dns.log row is CAR-worthy once it names a query (the resolved name); a
// malformed row with no query stays raw. Python:
//
//	return bool(rec.get("query"))
//
// `bool()` is Python truthiness, so "" / 0 / [] / {} / False / None / absent
// all decline and "-" (a non-empty string) CLAIMS — the blank-string rule the
// resolver applies is NOT in play here.
package predicates

import (
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("zeek_dns_is_query", zdnsIsQuery)
}

func zdnsIsQuery(r *record.Record) bool {
	return record.Truthy(r.Get("query"))
}
