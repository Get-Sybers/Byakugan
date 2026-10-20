package l1physical

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAssetIDPrecedence(t *testing.T) {
	cases := []struct {
		name                       string
		disk, vol, img, item, want string
	}{
		{"disk wins", "SER123", "{vol}", "abc", "file.jsonl", "SER123"},
		{"volume when no disk", "", "VOLGUID", "abc", "x", "VOLGUID"},
		{"image when no disk/vol", " ", "-", "SHA256VAL", "x", "SHA256VAL"},
		{"name fallback", "", "", "", "Users/Jake/NTUSER.DAT", "NTUSER.DAT"},
		{"name cleaned", "-", "", "", "weird name!.evtx", "weird_name_.evtx"},
		{"all blank", "", "-", "  ", "", ""},
		{"trims the winner", "  SER123  ", "", "", "", "SER123"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := AssetID(c.disk, c.vol, c.img, c.item)
			if got != c.want {
				t.Fatalf("AssetID(%q,%q,%q,%q) = %q, want %q",
					c.disk, c.vol, c.img, c.item, got, c.want)
			}
			sp := Spindle{DiskSerial: c.disk, VolumeGUID: c.vol, ImageSHA256: c.img, Name: c.item}
			if sp.AssetID() != c.want {
				t.Fatalf("Spindle.AssetID() = %q, want %q", sp.AssetID(), c.want)
			}
		})
	}
}

func TestCleanName(t *testing.T) {
	cases := map[string]string{
		"NTUSER.DAT":            "NTUSER.DAT",
		"C:\\Windows\\foo.evtx": "foo.evtx",
		"a/b/c.log":             "c.log",
		"weird name!.evtx":      "weird_name_.evtx",
		"  spaced  ":            "spaced",
		"---":                   "",
		"":                      "",
		"-":                     "",
	}
	for in, want := range cases {
		if got := CleanName(in); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSchemaEmbedded(t *testing.T) {
	if !strings.Contains(schemaDDL, "CREATE TABLE IF NOT EXISTS spindle") {
		t.Fatalf("embedded schema.sql missing the spindle table:\n%s", schemaDDL)
	}
	if Schema() != schemaDDL {
		t.Fatal("Schema() must return the embedded DDL")
	}
}

func openTemp(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Path(t.TempDir()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAppliesSchemaAndPragmas(t *testing.T) {
	db := openTemp(t)

	var userVersion int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if userVersion != 1 {
		t.Fatalf("user_version = %d, want 1", userVersion)
	}

	var journal string
	if err := db.db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if !strings.EqualFold(journal, "wal") {
		t.Fatalf("journal_mode = %q, want wal", journal)
	}

	var busy int
	if err := db.db.QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if busy != busyTimeoutMS {
		t.Fatalf("busy_timeout = %d, want %d", busy, busyTimeoutMS)
	}
}

func TestRegisterLookupUpsert(t *testing.T) {
	db := openTemp(t)
	sp := Spindle{
		CaseID: "case-A", HostID: "machine-guid-1", HostLabel: "WIN-1M3263ACE5D",
		DiskSerial: "SER123", VolumeGUID: "{vol-guid}", ImageSHA256: "deadbeef", Name: "evt.jsonl",
	}
	if err := db.Register(sp); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, found, err := db.Lookup("case-A", "SER123") // disk_serial is the asset-id
	if err != nil || !found {
		t.Fatalf("Lookup: found=%v err=%v", found, err)
	}
	if got.HostID != "machine-guid-1" || got.VolumeGUID != "{vol-guid}" || got.HostLabel != "WIN-1M3263ACE5D" {
		t.Fatalf("Lookup round-trip mismatch: %+v", got)
	}

	// registered_at stays put, updated_at moves, identity fields refresh.
	var reg1, upd1 string
	if err := db.db.QueryRow(
		"SELECT registered_at, updated_at FROM spindle WHERE case_id=? AND asset_id=?",
		"case-A", "SER123").Scan(&reg1, &upd1); err != nil {
		t.Fatalf("row read: %v", err)
	}
	sp.HostLabel = "DESKTOP-PM6C56D" // same host, a different fragmented label
	if err := db.Register(sp); err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	var reg2 string
	var count int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM spindle").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("upsert created a second row: count=%d", count)
	}
	if err := db.db.QueryRow(
		"SELECT registered_at FROM spindle WHERE case_id=? AND asset_id=?",
		"case-A", "SER123").Scan(&reg2); err != nil {
		t.Fatalf("row read 2: %v", err)
	}
	if reg2 != reg1 {
		t.Fatalf("registered_at changed on upsert: %q -> %q", reg1, reg2)
	}
	got, _, _ = db.Lookup("case-A", "SER123")
	if got.HostLabel != "DESKTOP-PM6C56D" {
		t.Fatalf("upsert did not refresh host_label: %q", got.HostLabel)
	}
}

func TestLookupAbsent(t *testing.T) {
	db := openTemp(t)
	_, found, err := db.Lookup("nope", "nope")
	if err != nil {
		t.Fatalf("Lookup err: %v", err)
	}
	if found {
		t.Fatal("found a row that was never registered")
	}
}

func TestRegisterRejectsBlankKeys(t *testing.T) {
	db := openTemp(t)
	if err := db.Register(Spindle{CaseID: "", DiskSerial: "x"}); err == nil {
		t.Fatal("expected an error for a blank case_id")
	}
	if err := db.Register(Spindle{CaseID: "c"}); err == nil {
		t.Fatal("expected ErrNoIdentity for a spindle with no identifying component")
	}
}

func TestGetBySpindle(t *testing.T) {
	db := openTemp(t)
	sp := Spindle{CaseID: "c", VolumeGUID: "VOL", Name: "n"}
	if err := db.Register(sp); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, found, err := db.Get(sp)
	if err != nil || !found {
		t.Fatalf("Get: found=%v err=%v", found, err)
	}
	if got.VolumeGUID != "VOL" {
		t.Fatalf("Get round-trip: %+v", got)
	}
}

func TestOpenReadIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	rw, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := rw.Register(Spindle{CaseID: "c", DiskSerial: "SER"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	rw.Close()

	ro, err := OpenRead(path)
	if err != nil {
		t.Fatalf("OpenRead: %v", err)
	}
	defer ro.Close()
	if _, found, err := ro.Lookup("c", "SER"); err != nil || !found {
		t.Fatalf("read-only Lookup: found=%v err=%v", found, err)
	}
	if err := ro.Register(Spindle{CaseID: "c", DiskSerial: "SER2"}); err == nil {
		t.Fatal("a write through a read-only handle must fail")
	}
}

func TestOpenReadMissing(t *testing.T) {
	_, err := OpenRead(filepath.Join(t.TempDir(), FileName))
	if err == nil {
		t.Fatal("OpenRead must report a missing registry, not create it")
	}
}

func TestStampFillOnly(t *testing.T) {
	sp := Spindle{
		HostID: "mg-1", DiskSerial: "SER", VolumeGUID: "VOL", ImageSHA256: "SHA",
	}
	rec := map[string]any{
		"host_id":     "already-set", // must be preserved
		"disk_serial": "",            // blank -> filled
		"other":       "untouched",
	}
	Stamp(rec, sp)
	if rec["host_id"] != "already-set" {
		t.Fatalf("Stamp overwrote an existing value: %v", rec["host_id"])
	}
	if rec["disk_serial"] != "SER" {
		t.Fatalf("Stamp did not fill a blank field: %v", rec["disk_serial"])
	}
	if rec["volume_guid"] != "VOL" || rec["image_sha256"] != "SHA" {
		t.Fatalf("Stamp did not fill absent fields: %+v", rec)
	}
	if rec["other"] != "untouched" {
		t.Fatalf("Stamp touched an unrelated field: %v", rec["other"])
	}
	Stamp(nil, sp) // must not panic
}

func TestPathAndFileName(t *testing.T) {
	if FileName != ".L1-physical.db" {
		t.Fatalf("FileName = %q", FileName)
	}
	if got := Path("/cases/x"); got != filepath.Join("/cases/x", FileName) {
		t.Fatalf("Path = %q", got)
	}
}
