// The byakugan/mappings/zeek_x509.py gate — zeek_x509_has_fingerprint.
//
// An x509.log row is CAR-worthy once it carries the fingerprint that identifies
// the certificate; a malformed row without one stays raw. Python:
//
//	return bool(rec.get("fingerprint"))
package predicates

import (
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("zeek_x509_has_fingerprint", zx509HasFingerprint)
}

func zx509HasFingerprint(r *record.Record) bool {
	return record.Truthy(r.Get("fingerprint"))
}
