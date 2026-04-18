package microsandbox

import (
	"testing"
	"time"
)

func TestFsEntryFields(t *testing.T) {
	e := FsEntry{Path: "/tmp/foo", Kind: "file", Size: 42, Mode: 0o644}
	if e.Path != "/tmp/foo" {
		t.Errorf("Path: got %q", e.Path)
	}
	if e.Kind != "file" {
		t.Errorf("Kind: got %q", e.Kind)
	}
	if e.Size != 42 {
		t.Errorf("Size: got %d", e.Size)
	}
	if e.Mode != 0o644 {
		t.Errorf("Mode: got %o", e.Mode)
	}
}

func TestFsStatFields(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	st := FsStat{
		Path:    "/tmp/bar",
		Size:    100,
		Mode:    0o755,
		ModTime: now,
		IsDir:   false,
	}
	if st.Path != "/tmp/bar" {
		t.Errorf("Path: got %q", st.Path)
	}
	if st.Size != 100 {
		t.Errorf("Size: got %d", st.Size)
	}
	if st.Mode != 0o755 {
		t.Errorf("Mode: got %o", st.Mode)
	}
	if !st.ModTime.Equal(now) {
		t.Errorf("ModTime: got %v, want %v", st.ModTime, now)
	}
	if st.IsDir {
		t.Error("IsDir should be false")
	}
}

func TestFsStatIsDir(t *testing.T) {
	st := FsStat{IsDir: true}
	if !st.IsDir {
		t.Error("IsDir should be true")
	}
}

func TestFsStatZeroModTime(t *testing.T) {
	st := FsStat{}
	if !st.ModTime.IsZero() {
		t.Error("zero-value ModTime should be zero time")
	}
}
