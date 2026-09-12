// The byakugan/mappings/zeek_extra.py gates — zeek_is_smtp_message (smtp.log →
// email) and zeek_is_file (files.log → file).
//
// Python:
//
//	def zeek_is_smtp_message(rec):
//	    return any(rec.get(k) for k in ("mailfrom", "rcptto", "from", "to", "subject"))
//
//	def zeek_is_file(rec):
//	    return bool(rec.get("fuid"))
//
// `any()` over a generator of raw values is Python truthiness per element, so a
// STARTTLS row (no envelope, no header, no subject) declines and stays raw
// rather than asserting a phantom `deliver` with no recipient. Note "" / 0 /
// [] / False decline while "-" claims — the resolver's blank rule is a separate
// layer and does not apply to the gate.
package predicates

import (
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("zeek_is_smtp_message", zextraIsSMTPMessage)
	Register("zeek_is_file", zextraIsFile)
}

// zextraSMTPContentKeys is the tuple zeek_is_smtp_message scans, in order.
var zextraSMTPContentKeys = []string{"mailfrom", "rcptto", "from", "to", "subject"}

func zextraIsSMTPMessage(r *record.Record) bool {
	for _, k := range zextraSMTPContentKeys {
		if record.Truthy(r.Get(k)) {
			return true
		}
	}
	return false
}

func zextraIsFile(r *record.Record) bool {
	return record.Truthy(r.Get("fuid"))
}
