// Package l1physical is byakugan's artefact spindle-identity registry: the
// L1-physical.db SQLite store that byakugan OWNS and both engines
// (godaemonhunter, gowindowlicker) and DX consume.
//
// One row per artefact/asset holds the evidence spindle — host -> disk ->
// volume -> image — captured at mount/collection time (the gomount manifest +
// gohost / the SOFTWARE-hive MachineGuid). It is the authoritative source for
// the asset-id that names the flat output (<subtool>/<asset-id>.jsonl) and for
// the physical-identity fields stamped on every record, superseding the
// per-lane host string that docs/CAR-CrossSource.md calls the master blocker
// ("host identity fragmented across lanes"). The knowledge-registry brief and
// byakugan#136 scope it; model/generate.py emits the DDL (schema.sql), which
// this package embeds, so the Go and Python consumers share one schema.
//
// The mechanics mirror DX_DFIR's collection .registry.db: the pure-Go
// modernc.org/sqlite driver (no cgo — FROM-scratch safe), opened "?mode=ro" to
// read and with foreign keys to write, plus WAL + busy_timeout because the lanes
// are separate, possibly-overlapping processes (decision 5). It is this repo's
// own Go module (github.com/Get-Sybers/Byakugan/go/l1physical) so pulling the
// SQLite dependency never touches the deliberately stdlib-only parse engine at
// go/.
//
// Decision 3 (byakugan ratifies): the raw per-asset spindle and the OS-native
// host_id are stored AS-IS; byakugan R2 reconciles host identity at read time;
// no cross-OS unification in v1.
package l1physical

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)
)

// schemaDDL is the registry DDL byakugan owns, emitted by model/generate.py
// (byakugan/l1physical.py:render_ddl) and embedded verbatim — the one schema the
// Python reader and this writer share.
//
//go:embed schema.sql
var schemaDDL string

// FileName is the on-disk name of a per-case registry. The logical db is
// "L1-physical.db" (decision 1); it is dot-prefixed so it stays outside
// byakugan's source-discovery walk (the .registry.db / _scratch lesson,
// decision 4).
const FileName = ".L1-physical.db"

// busyTimeoutMS is how long a writer waits on a locked db before giving up —
// the lanes are separate processes sharing one per-case file (decision 5).
const busyTimeoutMS = 5000

// Schema returns the embedded DDL byakugan owns.
func Schema() string { return schemaDDL }

// Path is the registry path for a case directory.
func Path(caseDir string) string { return filepath.Join(caseDir, FileName) }

// Spindle is one artefact/asset's evidence spindle identity, stored as-is:
// host -> disk -> volume -> image, scoped to a case. The disk/volume/image
// values come from the gomount manifest; HostID is the OS-native stable id
// (Win MachineGuid / Linux machine-id / mac hw-UUID); HostLabel is the human
// name (source_host / ComputerName) for R2's alias reconciliation, never a key.
type Spindle struct {
	CaseID      string
	HostID      string
	HostLabel   string
	DiskSerial  string
	VolumeGUID  string
	ImageSHA256 string
	Name        string
}

// AssetID is the per-asset key = the flat-output leaf: the first non-blank of
// disk_serial > volume_guid > image_sha256 > cleaned name.
func (s Spindle) AssetID() string {
	return AssetID(s.DiskSerial, s.VolumeGUID, s.ImageSHA256, s.Name)
}

// AssetID is the per-asset key for the given components: the first non-blank of
// disk_serial > volume_guid > image_sha256 > cleaned name (exactly the flat
// leaf). It returns "" when no component applies.
func AssetID(diskSerial, volumeGUID, imageSHA256, name string) string {
	for _, v := range []string{diskSerial, volumeGUID, imageSHA256} {
		if !blank(v) {
			return strings.TrimSpace(v)
		}
	}
	return CleanName(name)
}

// CleanName is the cleaned item-name fallback rung: a filesystem-safe leaf.
// Conservative — basename, every non-[A-Za-z0-9._-] run collapsed to '_',
// stripped of leading/trailing separators; "" when nothing survives. Mirrors
// byakugan.l1physical.clean_name.
func CleanName(name string) string {
	if blank(name) {
		return ""
	}
	s := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	var b strings.Builder
	prevUnsafe := false
	for _, r := range s {
		safe := r == '.' || r == '_' || r == '-' ||
			(r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		if safe {
			b.WriteRune(r)
			prevUnsafe = false
			continue
		}
		if !prevUnsafe {
			b.WriteByte('_')
			prevUnsafe = true
		}
	}
	return strings.Trim(b.String(), "._-")
}

// blank is byakugan's blank rule: "", whitespace and "-" are all blank.
func blank(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || t == "-"
}

// DB is an open L1-physical registry.
type DB struct{ db *sql.DB }

// Open opens the per-case registry read-write, creating it if absent, applying
// the embedded DDL (IF NOT EXISTS, a no-op on an existing store) with WAL +
// busy_timeout and foreign keys enforced — the .registry.db open discipline.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("l1physical: create registry dir: %w", err)
		}
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)",
		path, busyTimeoutMS)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("l1physical: open %q: %w", path, err)
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("l1physical: apply schema: %w", err)
	}
	return &DB{db: db}, nil
}

// OpenRead opens an existing registry read-only (mode=ro — a read never creates
// or mutates the store). A missing file is reported, not created.
func OpenRead(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("l1physical: open read-only %q: %w", path, err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("l1physical: open read-only %q: %w", path, err)
	}
	return &DB{db: db}, nil
}

// Close closes the registry.
func (d *DB) Close() error { return d.db.Close() }

// ErrNoIdentity is returned by Register when a spindle has neither a disk
// serial, volume GUID, image hash nor a name — nothing to key it by.
var ErrNoIdentity = errors.New("l1physical: spindle has no identifying component")

// Register upserts the spindle, keyed per-asset by (case_id, asset_id). A second
// registration of the same asset refreshes its identity fields and updated_at
// while keeping the original registered_at — an asset's physical identity is the
// same whoever parses it, so both engines register into one per-case store.
func (d *DB) Register(s Spindle) error {
	if blank(s.CaseID) {
		return errors.New("l1physical: spindle has no case_id")
	}
	assetID := s.AssetID()
	if assetID == "" {
		return ErrNoIdentity
	}
	now := nowUTC()
	_, err := d.db.Exec(
		`INSERT INTO spindle
		    (case_id, asset_id, host_id, host_label, disk_serial, volume_guid,
		     image_sha256, name, registered_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(case_id, asset_id) DO UPDATE SET
		     host_id      = excluded.host_id,
		     host_label   = excluded.host_label,
		     disk_serial  = excluded.disk_serial,
		     volume_guid  = excluded.volume_guid,
		     image_sha256 = excluded.image_sha256,
		     name         = excluded.name,
		     updated_at   = excluded.updated_at`,
		strings.TrimSpace(s.CaseID), assetID,
		nullable(s.HostID), nullable(s.HostLabel), nullable(s.DiskSerial),
		nullable(s.VolumeGUID), nullable(s.ImageSHA256), nullable(s.Name),
		now, now)
	if err != nil {
		return fmt.Errorf("l1physical: register %q: %w", assetID, err)
	}
	return nil
}

// Lookup returns the stored spindle for (caseID, assetID) and whether it was
// found.
func (d *DB) Lookup(caseID, assetID string) (Spindle, bool, error) {
	var (
		s                                                         Spindle
		hostID, hostLabel, diskSerial, volumeGUID, imageSHA, name sql.NullString
	)
	err := d.db.QueryRow(
		`SELECT case_id, host_id, host_label, disk_serial, volume_guid,
		        image_sha256, name
		   FROM spindle WHERE case_id = ? AND asset_id = ?`,
		strings.TrimSpace(caseID), assetID,
	).Scan(&s.CaseID, &hostID, &hostLabel, &diskSerial, &volumeGUID, &imageSHA, &name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Spindle{}, false, nil
	case err != nil:
		return Spindle{}, false, fmt.Errorf("l1physical: lookup %q: %w", assetID, err)
	}
	s.HostID = hostID.String
	s.HostLabel = hostLabel.String
	s.DiskSerial = diskSerial.String
	s.VolumeGUID = volumeGUID.String
	s.ImageSHA256 = imageSHA.String
	s.Name = name.String
	return s, true, nil
}

// Get is Lookup by a spindle's own case + asset-id (convenience for a caller
// that already holds the Spindle it registered).
func (d *DB) Get(s Spindle) (Spindle, bool, error) {
	return d.Lookup(s.CaseID, s.AssetID())
}

// StampFields names the physical-identity fields Stamp fills, in order.
var StampFields = []string{"host_id", "disk_serial", "volume_guid", "image_sha256"}

// Stamp fills the spindle's physical-identity fields onto rec BESIDE its native
// values — fill-only: a field already carrying a non-blank value is never
// overwritten (gopinfo decision 14 preserved). This is the authoritative form
// of what the Origin stamp does today from the manifest; the db takes only the
// physical-identity role (decision 7).
func Stamp(rec map[string]any, s Spindle) {
	if rec == nil {
		return
	}
	for field, value := range map[string]string{
		"host_id":      s.HostID,
		"disk_serial":  s.DiskSerial,
		"volume_guid":  s.VolumeGUID,
		"image_sha256": s.ImageSHA256,
	} {
		if blank(value) {
			continue
		}
		if cur, ok := rec[field]; ok && !blankAny(cur) {
			continue
		}
		rec[field] = value
	}
}

// --- helpers --- //

// nullable renders a blank value as SQL NULL, any other as its trimmed self, so
// the optional columns hold NULL rather than "" and the host index stays clean.
func nullable(s string) any {
	if blank(s) {
		return nil
	}
	return strings.TrimSpace(s)
}

// blankAny is blank() for a record value of unknown type: nil, "", whitespace
// and "-" are blank; any non-string value is present.
func blankAny(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	return blank(s)
}

// nowUTC is the registry timestamp format: UTC, second precision, trailing Z —
// matching the collection registry's _now().
func nowUTC() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }
