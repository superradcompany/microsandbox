package vfs

import (
	"fmt"
	"testing"
)

func TestValidateProviderPath(t *testing.T) {
	cases := []struct {
		path []byte
		ok   bool
	}{
		{[]byte("/"), true},
		{[]byte("/inbox/msg.txt"), true},
		{nil, false},
		{[]byte(""), false},
		{[]byte("inbox"), false},
		{[]byte("/inbox\x00"), false},
		{[]byte("/.."), false},
		{[]byte("/inbox/../etc"), false},
		{[]byte("/inbox//msg"), false},
		{[]byte("/inbox/./msg"), false},
		{[]byte("/."), false},
	}
	for _, tc := range cases {
		err := validateProviderPath(tc.path)
		if tc.ok && err != nil {
			t.Fatalf("validateProviderPath(%q): %v", tc.path, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("validateProviderPath(%q): expected error", tc.path)
		}
	}
}

func TestDispatchRejectsDotdotPath(t *testing.T) {
	resp := dispatch(stubPathFs{}, request{kind: rGetAttr, path: []byte("/inbox/../etc")}, &readDirCache{})
	if resp.kind != pErr {
		t.Fatalf("kind = %v, want pErr", resp.kind)
	}
}

func TestDispatchRejectsDotPathComponent(t *testing.T) {
	resp := dispatch(stubPathFs{}, request{kind: rGetAttr, path: []byte("/inbox/./msg")}, &readDirCache{})
	if resp.kind != pErr {
		t.Fatalf("kind = %v, want pErr", resp.kind)
	}
}

func TestMaxConcurrentOpsMatchesRust(t *testing.T) {
	// Keep in sync with MAX_PENDING_CALLS in
	// crates/filesystem/lib/backends/vfs/rpc/transport.rs.
	const rustMaxPendingCalls = 16
	if MaxConcurrentOps != rustMaxPendingCalls {
		t.Fatalf("MaxConcurrentOps = %d, want %d (Rust MAX_PENDING_CALLS)", MaxConcurrentOps, rustMaxPendingCalls)
	}
}

func TestServeShutdownWaitMatchesRust(t *testing.T) {
	// Keep in sync with SHUTDOWN_JOIN_TIMEOUT in
	// crates/filesystem/lib/backends/vfs/rpc/serve.rs.
	const rustShutdownJoinTimeoutSecs = 30
	if virtualMountServeShutdownWait.Seconds() != rustShutdownJoinTimeoutSecs {
		t.Fatalf("virtualMountServeShutdownWait = %v, want %ds", virtualMountServeShutdownWait, rustShutdownJoinTimeoutSecs)
	}
}

func TestMaxReaddirCachePathsMatchesRust(t *testing.T) {
	// Keep in sync with MAX_READDIR_CACHE_PATHS in
	// crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
	const rustMaxReaddirCachePaths = 64
	if maxReaddirCachePaths != rustMaxReaddirCachePaths {
		t.Fatalf("maxReaddirCachePaths = %d, want %d", maxReaddirCachePaths, rustMaxReaddirCachePaths)
	}
}

func TestMaxReaddirFetchRetriesMatchesRust(t *testing.T) {
	// Keep in sync with MAX_READDIR_FETCH_RETRIES in
	// crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
	const rustMaxReaddirFetchRetries = 64
	if maxReaddirFetchRetries != rustMaxReaddirFetchRetries {
		t.Fatalf("maxReaddirFetchRetries = %d, want %d", maxReaddirFetchRetries, rustMaxReaddirFetchRetries)
	}
}

func TestValidateSymlinkTarget(t *testing.T) {
	cases := []struct {
		target []byte
		ok     bool
	}{
		{[]byte("relative"), true},
		{[]byte("/abs/path"), false},
		{[]byte(".."), false},
		{[]byte("../etc"), false},
		{[]byte("/a/../b"), false},
		{[]byte("foo/.."), false},
		{[]byte("x\x00"), false},
	}
	for _, tc := range cases {
		err := validateSymlinkTarget(tc.target)
		if tc.ok && err != nil {
			t.Fatalf("validateSymlinkTarget(%q): %v", tc.target, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("validateSymlinkTarget(%q): expected error", tc.target)
		}
	}
}

type largeDirFs struct{ stubPathFs }

func (largeDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	if string(path) != "/big" {
		return nil, Err(ENOENT)
	}
	out := make([]DirEntry, 5000)
	for i := range out {
		out[i] = DirEntry{Name: []byte(fmt.Sprintf("f%04d", i)), Kind: File}
	}
	return out, nil
}

func TestReadDirPaginates(t *testing.T) {
	const page = maxReaddirEntries
	var cache readDirCache
	fs := largeDirFs{}
	resp := dispatch(fs, request{kind: rReadDir, path: []byte("/big"), offset: 0, size: uint32(page)}, &cache)
	if resp.kind != pDir || len(resp.dir) != page {
		t.Fatalf("first page: kind=%v len=%d want %d", resp.kind, len(resp.dir), page)
	}
	resp = dispatch(fs, request{kind: rReadDir, path: []byte("/big"), offset: page, size: uint32(page)}, &cache)
	if resp.kind != pDir || len(resp.dir) != 5000-page {
		t.Fatalf("second page: kind=%v len=%d want %d", resp.kind, len(resp.dir), 5000-page)
	}
}
