package normalize

import (
	"strings"
	"testing"

	"github.com/get-sybers/byakugan/go/internal/pyjson"
	"github.com/get-sybers/byakugan/go/internal/record"
)

// The _SEC_4624 record from tests/test_car.py — a sanity check that the full
// chain hangs together; byte-level parity is the tests/parity harness's job.
const sec4624 = `{"EventId": 4624, "Channel": "Security", "Computer": "HOST1.example.com",` +
	` "EventRecordId": 14, "TimeCreated": "2019-01-28T19:40:32+00:00", "UserName": "x",` +
	` "Payload": "{\"EventData\": {\"Data\": [` +
	`{\"@Name\": \"TargetUserName\", \"#text\": \"Steve\"},` +
	`{\"@Name\": \"SubjectUserName\", \"#text\": \"-\"},` +
	`{\"@Name\": \"WorkstationName\", \"#text\": \"DESKTOP-8\"},` +
	`{\"@Name\": \"TargetLogonId\", \"#text\": \"0x338F0\"},` +
	`{\"@Name\": \"ProcessName\", \"#text\": \"C:\\\\Windows\\\\System32\\\\svchost.exe\"}]}}"}`

func TestSecurity4624IsAuthenticationSuccess(t *testing.T) {
	v, err := pyjson.DecodeString(sec4624)
	if err != nil {
		t.Fatal(err)
	}
	rec := record.New(v.(*pyjson.Object))
	ev, err := Normalize("evtx_security", rec)
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil {
		t.Fatal("record dropped")
	}
	get := func(k string) pyjson.Value { v, _ := ev.Get(k); return v }
	if get("car_object") != "authentication" || get("car_action") != "success" {
		t.Fatalf("object/action: %v/%v", get("car_object"), get("car_action"))
	}
	if get("target_user") != "Steve" {
		t.Fatalf("target_user: %v", get("target_user"))
	}
	if get("user") != nil { // '-' is an honest blank
		t.Fatalf("user: %v", get("user"))
	}
	if get("source_host") != "HOST1" {
		t.Fatalf("source_host: %v", get("source_host"))
	}
	if get("app_name") != "svchost.exe" {
		t.Fatalf("app_name: %v", get("app_name"))
	}
	guid, _ := get("guid").(string)
	if !strings.HasPrefix(guid, "authentication-HOST1.example.com-Security-14") {
		t.Fatalf("guid: %v", guid)
	}
	native, _ := get("_native").(*pyjson.Object)
	if tl, _ := native.Get("TargetLogonId"); tl != "0x338F0" {
		t.Fatalf("TargetLogonId: %v", tl)
	}
	// Python event key order — the JSON contract downstream tools read
	wantHead := []string{"car_object", "car_action", "timestamp", "guid",
		"owning_pid", "owning_guid_native", "parent_pid", "owning_guid",
		"parent_guid", "link_confidence", "source_artefact", "source_host", "_native"}
	keys := ev.Keys()
	for i, w := range wantHead {
		if keys[i] != w {
			t.Fatalf("event key %d = %q, want %q (order contract)", i, keys[i], w)
		}
	}
}

func TestUnmappedAndDropped(t *testing.T) {
	v, _ := pyjson.DecodeString(`{"EventId": 4688, "Channel": "Security"}`)
	rec := record.New(v.(*pyjson.Object))
	ev, err := Normalize("evtx_security", rec)
	if err != nil || ev != nil {
		t.Fatalf("4688 should drop: ev=%v err=%v", ev, err)
	}
	ev, err = Normalize("no_such_map", rec)
	if err != nil || ev != nil {
		t.Fatalf("unknown artefact should be nil: ev=%v err=%v", ev, err)
	}
}
