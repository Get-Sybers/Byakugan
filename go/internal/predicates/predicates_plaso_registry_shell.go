// The variant gates of the three wrapped-plaso disk-artefact mapping modules
// that share one family here:
//
//	byakugan/mappings/plaso_registry.py   → plaso_is_registry        (plaso_registry)
//	byakugan/mappings/plaso_shellitem.py  → plasoshell_create/modify/read
//	byakugan/mappings/plaso_artifacts.py  → plasoart_lnk_create/modify/read,
//	                                        plasoart_recycle_delete
//
// All eight gates read the WRAPPED row's nested plaso `Record` dict, never the
// wrapper itself, and all but plaso_is_registry are `data_type == <literal>`
// AND a case-insensitive re.search over `timestamp_desc` — the same
// timestamp_desc discipline the filestat/LNK maps use.
package predicates

import (
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/pyre"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// The three modules compile the SAME three timestamp_desc patterns
// (plaso_shellitem.py and plaso_artifacts.py each keep their own copies);
// plaso_artifacts adds the deletion one.
var (
	prsTdCreate = pyre.MustCompile(`(?i)creation|crtime|birth`)
	prsTdModify = pyre.MustCompile(`(?i)modification|mtime`)
	prsTdRead   = pyre.MustCompile(`(?i)last access|atime|access time`)
	prsTdDelete = pyre.MustCompile(`(?i)deletion`)
)

const (
	prsShellDT   = "windows:shell_item:file_entry" // plaso_shellitem._DT
	prsLnkDT     = "windows:lnk:link"
	prsRecycleDT = "windows:metadata:deleted_item"
	prsRegPrefix = "windows:registry:"
)

func init() {
	Register("plaso_is_registry", prsIsRegistry)

	Register("plasoshell_create", func(r *record.Record) bool {
		return prsDataType(r, prsShellDT) && prsTdCreate.Matches(prsTd(r))
	})
	Register("plasoshell_modify", func(r *record.Record) bool {
		return prsDataType(r, prsShellDT) && prsTdModify.Matches(prsTd(r))
	})
	Register("plasoshell_read", func(r *record.Record) bool {
		return prsDataType(r, prsShellDT) && prsTdRead.Matches(prsTd(r))
	})

	Register("plasoart_lnk_create", func(r *record.Record) bool {
		return prsDataType(r, prsLnkDT) && prsTdCreate.Matches(prsTd(r))
	})
	Register("plasoart_lnk_modify", func(r *record.Record) bool {
		return prsDataType(r, prsLnkDT) && prsTdModify.Matches(prsTd(r))
	})
	Register("plasoart_lnk_read", func(r *record.Record) bool {
		return prsDataType(r, prsLnkDT) && prsTdRead.Matches(prsTd(r))
	})
	Register("plasoart_recycle_delete", func(r *record.Record) bool {
		return prsDataType(r, prsRecycleDT) && prsTdDelete.Matches(prsTd(r))
	})
}

// prsIsRegistry is plaso_registry.plaso_is_registry:
//
//	dt = str((rec.get("Record") or {}).get("data_type") or "")
//	return dt.startswith("windows:registry:")
//
// Note the `or {}` (not mappings._common.plaso_rec's isinstance check): a
// FALSY non-dict Record (None, {}, [], "", 0) reads as the empty dict, while a
// TRUTHY non-dict Record makes Python raise AttributeError. Go returns false
// there instead of panicking — the only divergence, and it is unreachable from
// the live lane (the L2tWinreg route always carries a dict Record). Recorded in
// the family report; no vector exercises it because Python cannot survive it.
func prsIsRegistry(r *record.Record) bool {
	var dtv pyjson.Value
	if rv := r.Get("Record"); record.Truthy(rv) {
		o, ok := rv.(*pyjson.Object)
		if !ok {
			return false
		}
		dtv, _ = o.Get("data_type")
	}
	dt := ""
	if record.Truthy(dtv) { // `... or ""`
		dt = record.PyStr(dtv)
	}
	return strings.HasPrefix(dt, prsRegPrefix)
}

// prsRec is mappings._common.plaso_rec: the nested plaso Record dict, or the
// empty dict when it is absent or not a dict (nil here — every reader below
// treats nil as empty).
func prsRec(r *record.Record) *pyjson.Object {
	o, _ := r.Get("Record").(*pyjson.Object)
	return o
}

// prsDataType is `_rec(rec).get("data_type") == "<literal>"` — a plain Python
// equality, so a non-string value never equals the literal.
func prsDataType(r *record.Record, want string) bool {
	o := prsRec(r)
	if o == nil {
		return false
	}
	v, _ := o.Get("data_type")
	s, ok := v.(string)
	return ok && s == want
}

// prsTd is the modules' _td: str(_rec(rec).get("timestamp_desc") or "").
func prsTd(r *record.Record) string {
	o := prsRec(r)
	if o == nil {
		return ""
	}
	v, _ := o.Get("timestamp_desc")
	if !record.Truthy(v) { // `... or ""`
		return ""
	}
	return record.PyStr(v)
}
