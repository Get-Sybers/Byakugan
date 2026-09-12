// Package adapt is the Go port of the two record-reshaping adapters the parse
// engine takes over from Python: byakugan/adapters/winevt.py (Plaso
// winevt(x) → EvtxECmd shape) and byakugan/adapters/jlecmd.py (JLECmd jump
// list → one record per DestListEntry).
//
// The frozen executable references the parity harness compares against live at
// tests/parity/reference/{winevt,jlecmd}.py — they, not this comment, are the
// spec. Every behaviour below is a line-for-line port of those modules.
package adapt

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

var (
	channelRe  = regexp.MustCompile(`<Channel>([^<]+)</Channel>`)
	computerRe = regexp.MustCompile(`<Computer>([^<]+)</Computer>`)
)

// winevtPlaceholder is winevt.py's `_P` — a positional slot the evtx maps
// never read, kept so the positions after it stay aligned.
const winevtPlaceholder = "_"

// winevtRule is one (channel keyword, EventId) → (shape, ordered field names)
// entry of winevt.RULES. Shape "E" is EventData.Data ([{@Name,#text}...]),
// shape "U" is UserData.EventXML ({name: value}).
type winevtRule struct {
	kw    string
	eid   int64
	shape string
	names []string
}

// winevtRules is winevt.RULES in DECLARATION order — `_rule` returns the FIRST
// entry whose EventId matches and whose channel keyword is a substring of
// "<channel> <source_name>", so the order is load-bearing (EventId 59 is both
// BITS and TerminalServices; 25 is both TS and Kernel-Boot).
var winevtRules = []winevtRule{
	// ---- Security channel: logon / privilege / process ----------------------
	{"Security", 4624, "E", []string{"SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName",
		"AuthenticationPackageName", "WorkstationName", "LogonGuid",
		"TransmittedServices", "LmPackageName", "KeyLength", "ProcessId",
		"ProcessName", "IpAddress", "IpPort"}},
	{"Security", 4625, "E", []string{"SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "Status", "FailureReason", "SubStatus", "LogonType",
		"LogonProcessName", "AuthenticationPackageName", "WorkstationName",
		"TransmittedServices", "LmPackageName", "KeyLength", "ProcessId",
		"ProcessName", "IpAddress", "IpPort"}},
	{"Security", 4634, "E", []string{"TargetUserSid", "TargetUserName",
		"TargetDomainName", "TargetLogonId", "LogonType"}},
	{"Security", 4647, "E", []string{"TargetUserSid", "TargetUserName",
		"TargetDomainName", "TargetLogonId"}},
	{"Security", 4672, "E", []string{"SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "PrivilegeList"}},
	{"Security", 4688, "E", []string{"SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName",
		"TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid",
		"TargetUserName", "TargetDomainName", "TargetLogonId", "ParentProcessName",
		"MandatoryLabel"}},
	{"Security", 4697, "E", []string{"SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "ServiceName", "ServiceFileName",
		"ServiceType", "ServiceStartType", "ServiceAccount"}},
	{"Security", 4778, "E", []string{"AccountName", "AccountDomain", "LogonID",
		"SessionName", "ClientName", "ClientAddress"}},
	{"Security", 4779, "E", []string{"AccountName", "AccountDomain", "LogonID",
		"SessionName", "ClientName", "ClientAddress"}},
	// ---- System channel: Service Control Manager ----------------------------
	{"System", 7045, "E", []string{"ServiceName", "ImagePath", "ServiceType",
		"StartType", "AccountName"}},
	// ---- BITS-Client: a transfer (HTTP download) ----------------------------
	{"Bits-Client", 59, "E", []string{"transferId", "name", "Id", "url", "peer",
		winevtPlaceholder,
		"fileTime", "fileLength", "bytesTotal", "bytesTransferred"}},
	{"Bits-Client", 60, "E", []string{"transferId", "name", "Id", "url", "peer",
		winevtPlaceholder,
		"fileTime", "fileLength", "bytesTotal", "bytesTransferred"}},
	// ---- TerminalServices: RDP/console session (UserData shape) -------------
	{"TerminalServices", 21, "U", []string{"User", "SessionID", "Address"}},
	{"TerminalServices", 24, "U", []string{"User", "SessionID", "Address"}},
	{"TerminalServices", 25, "U", []string{"User", "SessionID", "Address"}},
	// ---- Sysmon (channel Microsoft-Windows-Sysmon/Operational) --------------
	// Plaso prepends RuleName at [0], then the standard Sysmon EventData order.
	{"Sysmon", 1, "E", []string{"RuleName", "UtcTime", "ProcessGuid", "ProcessId",
		"Image", "FileVersion", "Description", "Product", "Company", "CommandLine",
		"CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId",
		"IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId",
		"ParentImage", "ParentCommandLine"}},
	{"Sysmon", 3, "E", []string{"RuleName", "UtcTime", "ProcessGuid", "ProcessId",
		"Image", "User", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp",
		"SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6",
		"DestinationIp", "DestinationHostname", "DestinationPort",
		"DestinationPortName"}},
	{"Sysmon", 5, "E", []string{"RuleName", "UtcTime", "ProcessGuid", "ProcessId",
		"Image"}},
	{"Sysmon", 6, "E", []string{"RuleName", "UtcTime", "ImageLoaded", "Hashes",
		"Signed", "Signature", "SignatureStatus"}},
	{"Sysmon", 7, "E", []string{"RuleName", "UtcTime", "ProcessGuid", "ProcessId",
		"Image", "ImageLoaded", "FileVersion", "Description", "Product",
		"Company", "Hashes", "Signed", "Signature", "SignatureStatus"}},
	{"Sysmon", 8, "E", []string{"RuleName", "UtcTime", "SourceProcessGuid",
		"SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId",
		"TargetImage", "NewThreadId", "StartAddress", "StartModule",
		"StartFunction"}},
	{"Sysmon", 11, "E", []string{"RuleName", "UtcTime", "ProcessGuid", "ProcessId",
		"Image", "TargetFilename", "CreationUtcTime"}},
	{"Sysmon", 12, "E", []string{"RuleName", "EventType", "UtcTime", "ProcessGuid",
		"ProcessId", "Image", "TargetObject"}},
	{"Sysmon", 13, "E", []string{"RuleName", "EventType", "UtcTime", "ProcessGuid",
		"ProcessId", "Image", "TargetObject", "Details"}},
	{"Sysmon", 23, "E", []string{"RuleName", "UtcTime", "ProcessGuid", "ProcessId",
		"User", "Image", "TargetFilename", "Hashes", "IsExecutable", "Archived"}},
}

// winevtRuleFor is winevt._rule: the first RULES entry whose EventId equals
// `eid` and whose channel keyword occurs in "<channel> <source>".
func winevtRuleFor(channel, source string, eid pyjson.Value) *winevtRule {
	hay := channel + " " + source
	for i := range winevtRules {
		r := &winevtRules[i]
		if winevtEidEq(eid, r.eid) && strings.Contains(hay, r.kw) {
			return r
		}
	}
	return nil
}

// winevtEidEq is Python `e == eid` with `e` an int literal: int and float
// compare numerically, bool is an int (True == 1), everything else is unequal.
func winevtEidEq(v pyjson.Value, e int64) bool {
	switch x := v.(type) {
	case bool:
		if x {
			return e == 1
		}
		return e == 0
	case *big.Int:
		return x.IsInt64() && x.Int64() == e
	case float64:
		return x == float64(e)
	default:
		return false
	}
}

// Winevt is winevt.adapt: one wrapped Plaso l2t row
// ({SourceImage, Timestamp, Parser, Record}) → an EvtxECmd-shaped record the
// evtx maps consume. (nil, nil) means "no CAR-relevant layout for this
// (channel, EventId)" — the caller leaves the row raw.
//
// An error is returned only where the Python adapter would raise (a non-string
// xml_string hits re.search's TypeError): a loud failure beats a silent
// divergence.
func Winevt(wrapped *pyjson.Object) (*pyjson.Object, error) {
	var rec *pyjson.Object
	if wrapped != nil {
		raw, _ := wrapped.Get("Record")
		if record.Truthy(raw) { // `wrapped.get("Record") or {}`
			o, ok := raw.(*pyjson.Object)
			if !ok {
				return nil, fmt.Errorf("winevt: Record is not a JSON object")
			}
			rec = o
		}
	}
	if rec == nil {
		rec = pyjson.NewObject()
	}
	get := func(k string) pyjson.Value { v, _ := rec.Get(k); return v }

	eid := get("event_identifier")

	xmlv := get("xml_string")
	xml := ""
	if record.Truthy(xmlv) { // `rec.get("xml_string") or ""`
		s, ok := xmlv.(string)
		if !ok {
			return nil, fmt.Errorf("winevt: xml_string is not a string")
		}
		xml = s
	}
	channel := ""
	if m := channelRe.FindStringSubmatch(xml); m != nil {
		channel = m[1]
	}

	sourceV := pyjson.Value("")
	if v := get("source_name"); record.Truthy(v) { // `... or ""`
		sourceV = v
	}
	rule := winevtRuleFor(channel, record.PyStr(sourceV), eid)
	if rule == nil {
		return nil, nil
	}

	var strs []pyjson.Value
	if lst, ok := get("strings").([]pyjson.Value); ok { // `if not isinstance(.., list)`
		strs = lst
	}
	val := func(i int) pyjson.Value {
		if i < len(strs) {
			return strs[i]
		}
		return nil
	}

	var payload pyjson.Value
	if rule.shape == "U" {
		inner := pyjson.NewObject()
		for i, nm := range rule.names {
			if nm == winevtPlaceholder {
				continue
			}
			inner.Set(nm, val(i))
		}
		ud := pyjson.NewObject()
		ud.Set("EventXML", inner)
		p := pyjson.NewObject()
		p.Set("UserData", ud)
		payload = p
	} else {
		data := make([]pyjson.Value, 0, len(rule.names))
		for i, nm := range rule.names {
			if nm == winevtPlaceholder {
				continue
			}
			d := pyjson.NewObject()
			d.Set("@Name", nm)
			d.Set("#text", val(i))
			data = append(data, d)
		}
		ed := pyjson.NewObject()
		ed.Set("Data", data)
		p := pyjson.NewObject()
		p.Set("EventData", ed)
		payload = p
	}

	// `rec.get("computer_name") or rec.get("hostname") or (<Computer> or None)`
	computer := pyjson.Value(nil)
	if v := get("computer_name"); record.Truthy(v) {
		computer = v
	} else if v := get("hostname"); record.Truthy(v) {
		computer = v
	} else if m := computerRe.FindStringSubmatch(xml); m != nil {
		computer = m[1]
	}

	// `channel or source` — the regex group is a str, so "" falls through.
	channelV := pyjson.Value(channel)
	if channel == "" {
		channelV = sourceV
	}

	var ts pyjson.Value
	if wrapped != nil {
		ts, _ = wrapped.Get("Timestamp")
	}

	out := pyjson.NewObject()
	out.Set("EventId", eid)
	// the Sysmon map gates on Provider ("sysmon" in Provider); Plaso's
	// source_name IS the provider (Microsoft-Windows-Sysmon)
	out.Set("Provider", sourceV)
	out.Set("Channel", channelV)
	out.Set("Computer", computer)
	out.Set("EventRecordId", get("record_number"))
	out.Set("TimeCreated", ts)
	out.Set("Payload", payload)
	out.Set("SourceFile", get("display_name"))
	out.Set("MapDescription", nil)
	return out, nil
}
