//go:build microsandbox_ffi_path

package microsandbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorageNativeMissingCatalogAndAcknowledgementRemainNonMutating(t *testing.T) {
	setupNative(t)
	directory := t.TempDir()
	home := filepath.Join(directory, "absent-home")
	t.Setenv("MSB_HOME", home)
	t.Setenv("MSB_CONFIG_PATH", filepath.Join(directory, "absent-config.json"))
	t.Setenv("MSB_BACKEND", "local")
	t.Setenv("MSB_PROFILE", "")
	if _, err := DiagnoseStorage(context.Background(), RuntimeConfig{Home: home}, StorageSelection{Names: []string{"app"}}); err == nil {
		t.Fatal("missing catalog was created")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("diagnosis changed missing home: %v", err)
	}
	options := StorageRecoveryOptions{Selections: []StorageRecoverySelection{{DiskID: "root", CandidateID: "view"}}}
	if _, err := RecoverStorage(context.Background(), "app", options); err == nil || !strings.Contains(err.Error(), "acknowledg") {
		t.Fatalf("recovery acknowledgement error: %v", err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("unacknowledged recovery changed home: %v", err)
	}
}

func TestStorageNativeDiagnosisReportLargerThanOneMiB(t *testing.T) {
	setupNative(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("requires Python 3 with sqlite3 to create an isolated catalog fixture")
	}
	home := t.TempDir()
	t.Setenv("MSB_HOME", home)
	t.Setenv("MSB_CONFIG_PATH", filepath.Join(home, "absent-config.json"))
	t.Setenv("MSB_BACKEND", "local")
	t.Setenv("MSB_PROFILE", "")
	// Each malformed saved config produces a valid per-sandbox diagnosis. The
	// maximum supported inventory with legal 128-byte names exceeds the old
	// one-MiB FFI buffer without creating disks, starting VMs or migrating rows.
	fixture := `import os, sqlite3, sys
home = sys.argv[1]
os.mkdir(os.path.join(home, "db"), 0o700)
path = os.path.join(home, "db", "msb.db")
with sqlite3.connect(path) as connection:
    connection.execute("CREATE TABLE sandbox(id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, config TEXT NOT NULL)")
    connection.executemany("INSERT INTO sandbox(name,status,config) VALUES(?,'Stopped','{}')", (("app-" + str(i).zfill(4) + "a" * 120,) for i in range(4096)))
os.chmod(path, 0o600)
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, python, "-c", fixture, home).CombinedOutput(); err != nil {
		t.Fatalf("create catalog fixture: %v\n%s", err, output)
	}
	catalog := filepath.Join(home, "db", "msb.db")
	before, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	report, err := DiagnoseStorage(ctx, RuntimeConfig{Home: home}, StorageSelection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= 1<<20 || len(report.Sandboxes) != 4096 {
		t.Fatalf("report is not the complete oversized fixture: bytes = %d, sandboxes = %d", len(encoded), len(report.Sandboxes))
	}
	for _, sandbox := range report.Sandboxes {
		if len(sandbox.Name) != 128 || sandbox.Status != StorageUnavailable || sandbox.Reason == nil || *sandbox.Reason != "invalid_configuration" || sandbox.Inspection != nil {
			t.Fatalf("unexpected per-sandbox diagnosis: %+v", sandbox)
		}
	}
	after, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("diagnosis or its buffer retry changed the catalog")
	}
	if _, err := os.Stat(filepath.Join(home, "sbx")); !os.IsNotExist(err) {
		t.Fatalf("diagnosis created sandbox state: %v", err)
	}
}
