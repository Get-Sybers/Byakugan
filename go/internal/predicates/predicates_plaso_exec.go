// Variant predicates of byakugan/mappings/plaso_exec.py — the wrapped-l2t
// execution-evidence family (plaso_exec_prefetch / plaso_exec_winreg /
// plaso_exec_cron), ported clause by clause.
//
// Every gate reads the WRAPPED row: the flat plaso event lives under "Record"
// and the per-parser table name under "Parser". Two shared Python helpers do
// the reading, and both use `or ""` (NOT `.get(key, "")`), so a present-but-
// falsy value renders as "" rather than Python's str() of it:
//
//	_parser(rec)         = str(rec.get("Parser") or "").lower()
//	_timestamp_desc(rec) = str((rec.get("Record") or {}).get("timestamp_desc") or "")
package predicates

import (
	"regexp"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

func init() {
	Register("plaso_is_prefetch_execution", plasoIsPrefetchExecution)
	Register("plaso_is_amcache_link_time", plasoIsAmcacheLinkTime)
	Register("plaso_is_amcache", plasoIsAmcache)
	Register("plaso_is_userassist_run", plasoIsUserassistRun)
	Register("plaso_is_bam", plasoIsBam)
	Register("plaso_is_appcompatcache", plasoIsAppcompatcache)
	Register("plaso_is_cron_task_run", plasoIsCronTaskRun)
}

// plasoExecCompileStamp is plaso_exec._COMPILE_STAMP: re.compile(r"(?i)link|compil")
// — plaso's "Link Time" (definitions.TIME_DESCRIPTION_LINK_TIME), tolerant of a
// "Compilation Time" rendering. An unanchored re.search.
var plasoExecCompileStamp = regexp.MustCompile(`(?i)link|compil`)

// plasoExecBamToken is plaso_is_bam's r"(?:^|/)bam(?:/|$)" — "bam" as a path
// SEGMENT of the parser name ("winreg/bam"), never a substring ("bamboo").
var plasoExecBamToken = regexp.MustCompile(`(?:^|/)bam(?:/|$)`)

// plasoIsPrefetchExecution: L2tPrefetch carries both windows:volume:creation
// (volume metadata, no program) and windows:prefetch:execution — only the
// latter is a run.
func plasoIsPrefetchExecution(r *record.Record) bool {
	return plasoExecDataTypeIs(r, "windows:prefetch:execution")
}

// plasoIsCronTaskRun: only syslog:cron:task_run lines are executions.
func plasoIsCronTaskRun(r *record.Record) bool {
	return plasoExecDataTypeIs(r, "syslog:cron:task_run")
}

// plasoIsAmcacheLinkTime: the amcache row whose timestamp is the program's PE
// "Link Time" — the header TimeDateStamp (when the binary was COMPILED).
func plasoIsAmcacheLinkTime(r *record.Record) bool {
	return strings.Contains(plasoExecParser(r), "amcache") &&
		plasoExecCompileStamp.MatchString(plasoExecTimestampDesc(r))
}

// plasoIsAmcache: an amcache row that EVIDENCES execution — every dated row of
// an entry EXCEPT the Link Time one.
func plasoIsAmcache(r *record.Record) bool {
	return strings.Contains(plasoExecParser(r), "amcache") && !plasoIsAmcacheLinkTime(r)
}

// plasoIsUserassistRun: only userassist rows that EVIDENCE a program run.
// XP-format `UEME_RUNPATH:<path>` maps; the other UEME_ counters/PIDL/CPL
// forms do not; Win7+ plaso decodes the value name to the bare path (no UEME_
// prefix) and those map too.
func plasoIsUserassistRun(r *record.Record) bool {
	if !strings.Contains(plasoExecParser(r), "userassist") {
		return false
	}
	vn := plasoExecRecStr(r, "value_name")
	return strings.HasPrefix(vn, "UEME_RUNPATH:") ||
		(vn != "" && !strings.HasPrefix(vn, "UEME_"))
}

// plasoIsBam matches "bam" as a parser path segment.
func plasoIsBam(r *record.Record) bool {
	return plasoExecBamToken.MatchString(plasoExecParser(r))
}

// plasoIsAppcompatcache is the plain substring test the Python does.
func plasoIsAppcompatcache(r *record.Record) bool {
	return strings.Contains(plasoExecParser(r), "appcompatcache")
}

// --- the two wrapped-row readers --------------------------------------------

// plasoExecRecField is `(rec.get("Record") or {}).get(key)`. A Record that is
// not a dict yields nil here; Python would raise AttributeError on a TRUTHY
// non-dict (a shape the plaso lane never emits — see the report's deviations).
func plasoExecRecField(r *record.Record, key string) pyjson.Value {
	o, ok := r.Get("Record").(*pyjson.Object)
	if !ok {
		return nil
	}
	v, _ := o.Get(key)
	return v
}

// plasoExecDataTypeIs is `record.get("data_type") == "<literal>"` — a string
// comparison, so a non-string data_type never matches.
func plasoExecDataTypeIs(r *record.Record, want string) bool {
	s, ok := plasoExecRecField(r, "data_type").(string)
	return ok && s == want
}

// plasoExecParser is _parser: str(rec.get("Parser") or "").lower().
func plasoExecParser(r *record.Record) string {
	v := r.Get("Parser")
	if !record.Truthy(v) { // `or ""` — None/""/0/False all become ""
		return ""
	}
	return strings.ToLower(record.PyStr(v))
}

// plasoExecTimestampDesc is _timestamp_desc.
func plasoExecTimestampDesc(r *record.Record) string {
	return plasoExecRecStr(r, "timestamp_desc")
}

// plasoExecRecStr is str((rec.get("Record") or {}).get(key) or "").
func plasoExecRecStr(r *record.Record, key string) string {
	v := plasoExecRecField(r, key)
	if !record.Truthy(v) {
		return ""
	}
	return record.PyStr(v)
}
