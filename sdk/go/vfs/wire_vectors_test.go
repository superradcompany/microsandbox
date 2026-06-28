package vfs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type wireFixtures struct {
	ProtocolVersion uint32 `json:"protocol_version"`
	HelloHex        string `json:"hello_hex"`
	GetAttrHex      string `json:"getattr_hex"`
	WriteHex        string `json:"write_hex"`
	GetAttrManyHex  string `json:"getattr_many_hex"`
	StatFsHex       string `json:"statfs_hex"`
	FlushHex        string `json:"flush_hex"`
	FsyncTrueHex    string `json:"fsync_true_hex"`
	FsyncFalseHex   string `json:"fsync_false_hex"`
	FsyncDirHex     string `json:"fsyncdir_hex"`
}

func loadWireFixtures(t *testing.T) wireFixtures {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "testdata", "wire_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fx wireFixtures
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	return fx
}

func TestWireVectorFixturesMatchEncoders(t *testing.T) {
	fx := loadWireFixtures(t)
	if fx.ProtocolVersion != protocolVersion {
		t.Fatalf("protocol_version = %d, want %d", fx.ProtocolVersion, protocolVersion)
	}

	assertHexEqual(t, "hello", fx.HelloHex, func() []byte {
		var buf [8]byte
		copy(buf[:4], helloMagic[:])
		putU32BE(buf[4:], protocolVersion)
		return buf[:]
	}())

	assertHexEqual(t, "getattr", fx.GetAttrHex, encodeRequest(request{
		kind: rGetAttr, path: []byte("/dir/file"),
	}))

	assertHexEqual(t, "write", fx.WriteHex, encodeRequest(request{
		kind: rWrite, path: []byte("/some/file"), offset: 42, data: []byte("hello world payload"),
	}))

	assertHexEqual(t, "getattr_many", fx.GetAttrManyHex, encodeRequest(request{
		kind: rGetAttrMany, paths: [][]byte{[]byte("/a"), []byte("/bb")},
	}))

	assertHexEqual(t, "statfs", fx.StatFsHex, encodeRequest(request{kind: rStatFs}))

	assertHexEqual(t, "flush", fx.FlushHex, encodeRequest(request{
		kind: rFlush, path: []byte("/f"),
	}))

	assertHexEqual(t, "fsync_true", fx.FsyncTrueHex, encodeRequest(request{
		kind: rFsync, path: []byte("/f"), flags: 1,
	}))

	assertHexEqual(t, "fsync_false", fx.FsyncFalseHex, encodeRequest(request{
		kind: rFsync, path: []byte("/f"),
	}))

	assertHexEqual(t, "fsyncdir", fx.FsyncDirHex, encodeRequest(request{
		kind: rFsyncDir, path: []byte("/d"),
	}))
}

func putU32BE(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func assertHexEqual(t *testing.T, name, wantHex string, got []byte) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("%s: decode hex: %v", name, err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s: CBOR mismatch\nwant %x\ngot  %x", name, want, got)
	}
}
