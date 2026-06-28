package vfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

//--------------------------------------------------------------------------------------------------
// Round-trips (Go encode -> Go decode)
//--------------------------------------------------------------------------------------------------

func TestRequestRoundTrip(t *testing.T) {
	reqs := []request{
		{kind: rGetAttr, path: []byte("/a")},
		{kind: rGetAttrMany, paths: [][]byte{[]byte("/a"), []byte("/b")}},
		{kind: rRead, path: []byte("/a"), offset: 42, size: 100},
		{kind: rWrite, path: []byte("/a"), offset: 7, data: []byte{0, 0xff, 'x'}},
		{kind: rCreate, path: []byte("/a"), attr: attrToWire(Attr{Kind: File, Mode: 0o644, Nlink: 1})},
		{kind: rMkdir, path: []byte("/d"), mode: 0o755},
		{kind: rRename, from: []byte("/a"), to: []byte("/b")},
		{kind: rSetAttr, path: []byte("/a"), valid: uint32(SetSize), attr: attrToWire(Attr{Size: 9})},
		{kind: rSymlink, path: []byte("/l"), target: []byte("/t")},
		{kind: rSetXattr, path: []byte("/a"), name: []byte("user.x"), value: []byte("v"), flags: 1},
		{kind: rListXattr, path: []byte("/a")},
		{kind: rStatFs},
	}
	for _, want := range reqs {
		got, err := decodeRequest(encodeRequest(want))
		if err != nil {
			t.Fatalf("kind %d: decode: %v", want.kind, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("kind %d: round-trip mismatch:\n got %+v\nwant %+v", want.kind, got, want)
		}
	}
}

func TestResponseRoundTrip(t *testing.T) {
	resps := []response{
		{kind: pAttr, attr: attrToWire(Attr{Kind: Dir, Mode: 0o755, Nlink: 2})},
		{kind: pAttrMany, attrMany: []attrResult{
			{ok: true, attr: attrToWire(Attr{Kind: File, Mode: 0o644, Nlink: 1})},
			{errno: ENOENT},
		}},
		{kind: pDir, dir: []dirEntryWire{{name: []byte("a"), kind: uint8(File)}, {name: []byte("d"), kind: uint8(Dir)}}},
		{kind: pBytes, data: []byte("hello")},
		{kind: pNames, names: [][]byte{[]byte("user.a"), []byte("user.b")}},
		{kind: pCount, count: 11},
		{kind: pStatFs, statfs: statFsWire{bsize: 4096, frsize: 4096, namemax: 255}},
		{kind: pOk},
		{kind: pErr, errno: ENOENT},
	}
	for _, want := range resps {
		got, err := decodeResponse(encodeResponse(want))
		if err != nil {
			t.Fatalf("kind %d: decode: %v", want.kind, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("kind %d: round-trip mismatch:\n got %+v\nwant %+v", want.kind, got, want)
		}
	}
}

//--------------------------------------------------------------------------------------------------
// Cross-language fixtures (bytes emitted by the Rust `ciborium` encoder)
//--------------------------------------------------------------------------------------------------

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRustRequestFixtures(t *testing.T) {
	// Re-encoding the decoded value must reproduce the Rust bytes exactly,
	// which proves both decode and encode are wire-compatible with ciborium.
	cases := []struct {
		name string
		hex  string
		want request
	}{
		{"read", "a16452656164a36470617468422f61666f6666736574182a6473697a651864",
			request{kind: rRead, path: []byte("/a"), offset: 42, size: 100}},
		{"getattrmany", "a16b476574417474724d616e79a165706174687382422f61422f62",
			request{kind: rGetAttrMany, paths: [][]byte{[]byte("/a"), []byte("/b")}}},
		{"statfs", "66537461744673", request{kind: rStatFs}},
	}
	for _, c := range cases {
		fixture := mustHex(t, c.hex)
		got, err := decodeRequest(fixture)
		if err != nil {
			t.Fatalf("%s: decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: decoded\n got %+v\nwant %+v", c.name, got, c.want)
		}
		if reenc := encodeRequest(got); !bytes.Equal(reenc, fixture) {
			t.Fatalf("%s: re-encode mismatch:\n got %x\nwant %x", c.name, reenc, fixture)
		}
	}
}

func TestRustResponseFixtures(t *testing.T) {
	attr := attrWire{
		kind: 1, mode: 0o755, size: 0, uid: 7, gid: 9,
		nlinkSet: true, nlink: 2, rdev: 0,
		atime: optTime{set: true, sec: 123, nsec: 456},
		mtime: optTime{},
		ctime: optTime{set: true, sec: -5, nsec: 0},
	}
	cases := []struct {
		name string
		hex  string
		want response
	}{
		{"attr", "a16441747472aa646b696e6401646d6f64651901ed6473697a650063756964076367696409656e6c696e6b02647264657600656174696d6582187b1901c8656d74696d65f6656374696d65822400",
			response{kind: pAttr, attr: attr}},
		{"ok", "624f6b", response{kind: pOk}},
		{"err", "a16345727202", response{kind: pErr, errno: 2}},
		{"attrmany", "a168417474724d616e7982a1624f6baa646b696e6400646d6f64651901a46473697a650063756964006367696400656e6c696e6b01647264657600656174696d65f6656d74696d65f6656374696d65f6a16345727202",
			response{kind: pAttrMany, attrMany: []attrResult{
				{ok: true, attr: attrWire{kind: 0, mode: 0o644, nlinkSet: true, nlink: 1}},
				{errno: 2},
			}}},
	}
	for _, c := range cases {
		fixture := mustHex(t, c.hex)
		got, err := decodeResponse(fixture)
		if err != nil {
			t.Fatalf("%s: decode: %v", c.name, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: decoded\n got %+v\nwant %+v", c.name, got, c.want)
		}
		if reenc := encodeResponse(got); !bytes.Equal(reenc, fixture) {
			t.Fatalf("%s: re-encode mismatch:\n got %x\nwant %x", c.name, reenc, fixture)
		}
	}
}

func TestPreEpochTimeWireRoundTrip(t *testing.T) {
	// Matches crates/filesystem vfs::rpc::protocol time_round_trips tests.
	cases := []struct {
		t        time.Time
		wantSec  int64
		wantNsec uint32
	}{
		{time.Unix(0, 0), 0, 0},
		{time.Unix(0, 0).Add(1000*time.Second + 500*time.Millisecond), 1000, 500000000},
		{time.Unix(0, 0).Add(-500 * time.Millisecond), -1, 500000000},
		{time.Unix(0, 0).Add(-1500 * time.Millisecond), -2, 500000000},
		{time.Unix(0, 0).Add(-2 * time.Second), -2, 0},
	}
	for _, c := range cases {
		o := optTimeOf(c.t)
		if o.sec != c.wantSec || o.nsec != c.wantNsec {
			t.Fatalf("%v: wire (%d, %d), want (%d, %d)", c.t, o.sec, o.nsec, c.wantSec, c.wantNsec)
		}
		if !o.toTime().Equal(c.t) {
			t.Fatalf("%v: round-trip got %v", c.t, o.toTime())
		}
	}
}

//--------------------------------------------------------------------------------------------------
// Serve loop against an in-memory provider over net.Pipe
//--------------------------------------------------------------------------------------------------

type memNode struct {
	kind   NodeKind
	mode   uint32
	data   []byte
	target []byte
}

type memFs struct {
	ReadOnly
	mu sync.Mutex
	m  map[string]*memNode
}

func newMemFs() *memFs {
	return &memFs{m: map[string]*memNode{"/": {kind: Dir, mode: 0o755}}}
}

func parentOf(p string) string {
	i := bytes.LastIndexByte([]byte(p), '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func (f *memFs) attrOf(n *memNode) Attr {
	size := uint64(0)
	if n.kind == File {
		size = uint64(len(n.data))
	}
	return Attr{Kind: n.kind, Mode: n.mode, Size: size}
}

func (f *memFs) GetAttr(path []byte) (Attr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.m[string(path)]
	if !ok {
		return Attr{}, Err(ENOENT)
	}
	return f.attrOf(n), nil
}

func (f *memFs) ReadDir(path []byte) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := string(path)
	if n, ok := f.m[k]; !ok || n.kind != Dir {
		if !ok {
			return nil, Err(ENOENT)
		}
		return nil, Err(ENOTDIR)
	}
	var out []DirEntry
	for child, n := range f.m {
		if child != k && parentOf(child) == k {
			name := child[bytes.LastIndexByte([]byte(child), '/')+1:]
			out = append(out, DirEntry{Name: []byte(name), Kind: n.kind})
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Name) < string(out[j].Name) })
	return out, nil
}

func (f *memFs) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.m[string(path)]
	if !ok {
		return nil, Err(ENOENT)
	}
	if offset >= uint64(len(n.data)) {
		return nil, nil
	}
	end := min(offset+uint64(size), uint64(len(n.data)))
	return append([]byte(nil), n.data[offset:end]...), nil
}

func (f *memFs) Write(path []byte, offset uint64, data []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.m[string(path)]
	if !ok {
		return 0, Err(ENOENT)
	}
	end := int(offset) + len(data)
	if end > len(n.data) {
		n.data = append(n.data, make([]byte, end-len(n.data))...)
	}
	copy(n.data[offset:end], data)
	return len(data), nil
}

func (f *memFs) Create(path []byte, attr Attr) (Attr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := string(path)
	if k == "/" {
		return Attr{}, Err(EEXIST)
	}
	parent := parentOf(k)
	pn, ok := f.m[parent]
	if !ok {
		return Attr{}, Err(ENOENT)
	}
	if pn.kind != Dir {
		return Attr{}, Err(ENOTDIR)
	}
	if _, ok := f.m[k]; ok {
		return Attr{}, Err(EEXIST)
	}
	n := &memNode{kind: attr.Kind, mode: attr.Mode}
	f.m[k] = n
	return f.attrOf(n), nil
}

func (f *memFs) Mkdir(path []byte, mode uint32) (Attr, error) {
	return f.Create(path, Attr{Kind: Dir, Mode: mode})
}

func (f *memFs) Rename(from, to []byte) error {
	return f.RenameWithFlags(from, to, 0)
}

func (f *memFs) RenameWithFlags(from, to []byte, flags uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fromP, toP := string(from), string(to)
	if _, ok := f.m[fromP]; !ok {
		return Err(ENOENT)
	}
	if flags&RenameNoReplace != 0 && fromP != toP {
		if _, ok := f.m[toP]; ok {
			return Err(EEXIST)
		}
	}
	if _, ok := f.m[toP]; ok {
		return Err(EEXIST)
	}
	f.m[toP] = f.m[fromP]
	delete(f.m, fromP)
	return nil
}

// serveTest wires a client conn to a Serve goroutine and returns a round-trip
// helper plus a cleanup.
func serveTest(t *testing.T, fs PathFs) (func(request) response, func()) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, fs) }()

	// Requester half of the handshake (the runtime's RpcPathFs does this in
	// production): write our hello, then read and validate the peer's.
	if err := writeHello(client); err != nil {
		t.Fatalf("writeHello: %v", err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatalf("readHello: %v", err)
	}

	var id uint64
	rt := func(req request) response {
		id++
		if err := writeFrame(client, id, encodeRequest(req)); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
		rid, respBytes, err := readFrame(client)
		if err != nil {
			t.Fatalf("readFrame: %v", err)
		}
		if rid != id {
			t.Fatalf("response id %d != request id %d", rid, id)
		}
		resp, err := decodeResponse(respBytes)
		if err != nil {
			t.Fatalf("decodeResponse: %v", err)
		}
		return resp
	}
	cleanup := func() {
		client.Close()
		if err := <-done; err != nil && err != io.EOF {
			t.Errorf("Serve returned: %v", err)
		}
	}
	return rt, cleanup
}

func TestServeRoundTrip(t *testing.T) {
	rt, cleanup := serveTest(t, newMemFs())
	defer cleanup()
	if r := rt(request{kind: rCreate, path: []byte("/f.txt"), attr: attrToWire(Attr{Kind: File, Mode: 0o644})}); r.kind != pAttr {
		t.Fatalf("create: %+v", r)
	}
	// write
	if r := rt(request{kind: rWrite, path: []byte("/f.txt"), offset: 0, data: []byte("hello world")}); r.kind != pCount || r.count != 11 {
		t.Fatalf("write: %+v", r)
	}
	// read back
	r := rt(request{kind: rRead, path: []byte("/f.txt"), offset: 0, size: 1024})
	if r.kind != pBytes || string(r.data) != "hello world" {
		t.Fatalf("read: %+v (%q)", r, r.data)
	}
	// partial read at offset
	r = rt(request{kind: rRead, path: []byte("/f.txt"), offset: 6, size: 5})
	if r.kind != pBytes || string(r.data) != "world" {
		t.Fatalf("read offset: %q", r.data)
	}
	// missing -> ENOENT
	if r := rt(request{kind: rGetAttr, path: []byte("/missing")}); r.kind != pErr || r.errno != ENOENT {
		t.Fatalf("getattr missing: %+v", r)
	}
}

func TestServeMalformedRequestReturnsEinval(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, newMemFs()) }()

	if err := writeHello(client); err != nil {
		t.Fatalf("writeHello: %v", err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatalf("readHello: %v", err)
	}

	if err := writeFrame(client, 1, []byte{0xff}); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	rid, respBytes, err := readFrame(client)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if rid != 1 {
		t.Fatalf("response id %d != request id 1", rid)
	}
	resp, err := decodeResponse(respBytes)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if resp.kind != pErr || resp.errno != EINVAL {
		t.Fatalf("malformed request response = %+v, want EINVAL", resp)
	}

	client.Close()
	if err := <-done; err != nil && err != io.EOF {
		t.Errorf("Serve returned: %v", err)
	}
}

func TestServeGetAttrMany(t *testing.T) {
	rt, cleanup := serveTest(t, newMemFs())
	defer cleanup()

	if r := rt(request{kind: rCreate, path: []byte("/f.txt"), attr: attrToWire(Attr{Kind: File, Mode: 0o644})}); r.kind != pAttr {
		t.Fatalf("create: %+v", r)
	}
	r := rt(request{kind: rGetAttrMany, paths: [][]byte{[]byte("/f.txt"), []byte("/missing")}})
	if r.kind != pAttrMany {
		t.Fatalf("getattrmany kind: %+v", r)
	}
	if len(r.attrMany) != 2 {
		t.Fatalf("len(attrMany) = %d, want 2", len(r.attrMany))
	}
	// Existing entry: attributes; missing entry: an in-band ENOENT, not a
	// whole-batch failure.
	if !r.attrMany[0].ok || NodeKind(r.attrMany[0].attr.kind) != File {
		t.Fatalf("entry 0 = %+v", r.attrMany[0])
	}
	if r.attrMany[1].ok || r.attrMany[1].errno != ENOENT {
		t.Fatalf("entry 1 = %+v, want errno ENOENT", r.attrMany[1])
	}
}

type panicFs struct {
	*memFs
}

func (p *panicFs) GetAttr(path []byte) (Attr, error) {
	panic("provider panic")
}

func TestWriteFrameFlushesWhenSupported(t *testing.T) {
	var buf flushRecorder
	payload := []byte("payload")
	if err := writeFrame(&buf, 1, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if buf.flushes != 1 {
		t.Fatalf("flushes = %d, want 1", buf.flushes)
	}
}

type flushRecorder struct {
	buf     []byte
	flushes int
}

func (f *flushRecorder) Write(p []byte) (int, error) {
	f.buf = append(f.buf, p...)
	return len(p), nil
}

func (f *flushRecorder) Flush() error {
	f.flushes++
	return nil
}

func TestServeExitsAfterResponseWriteFailure(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, newMemFs()) }()

	if err := writeHello(client); err != nil {
		t.Fatalf("writeHello: %v", err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatalf("readHello: %v", err)
	}
	if err := writeFrame(client, 1, encodeRequest(request{kind: rGetAttr, path: []byte("/")})); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	// Drop the client without reading the reply so the server's write fails.
	client.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case err := <-done:
			if err != nil && err != io.EOF {
				t.Errorf("Serve returned: %v", err)
			}
			return
		default:
			if time.Now().After(deadline) {
				t.Fatal("Serve did not exit after response write failure")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestServeRecoversFromProviderPanic(t *testing.T) {
	rt, cleanup := serveTest(t, &panicFs{memFs: newMemFs()})
	defer cleanup()

	r := rt(request{kind: rGetAttr, path: []byte("/")})
	if r.kind != pErr || r.errno != EIO {
		t.Fatalf("panic getattr: %+v", r)
	}
}

func TestServeWithErrorLogCapturesPanic(t *testing.T) {
	client, server := net.Pipe()
	logged := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(server, &panicFs{memFs: newMemFs()}, WithErrorLog(func(format string, args ...any) {
			select {
			case logged <- fmt.Sprintf(format, args...):
			default:
			}
		}))
	}()

	if err := writeHello(client); err != nil {
		t.Fatalf("writeHello: %v", err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatalf("readHello: %v", err)
	}
	if err := writeFrame(client, 1, encodeRequest(request{kind: rGetAttr, path: []byte("/")})); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	_, respBytes, err := readFrame(client)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	resp, err := decodeResponse(respBytes)
	if err != nil {
		t.Fatalf("decodeResponse: %v", err)
	}
	if resp.kind != pErr || resp.errno != EIO {
		t.Fatalf("panic getattr: %+v", resp)
	}

	// The panic must reach the injected logger, not the global one.
	select {
	case msg := <-logged:
		if !strings.Contains(msg, "provider panic") {
			t.Fatalf("custom logger got %q, want it to mention the panic", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("custom error logger was not invoked on provider panic")
	}

	client.Close()
	if err := <-done; err != nil && err != io.EOF {
		t.Errorf("Serve returned: %v", err)
	}
}

func TestServeReaddir(t *testing.T) {
	rt, cleanup := serveTest(t, newMemFs())
	defer cleanup()

	rt(request{kind: rMkdir, path: []byte("/d"), mode: 0o755})
	rt(request{kind: rCreate, path: []byte("/d/a.txt"), attr: attrToWire(Attr{Kind: File, Mode: 0o644})})
	rt(request{kind: rCreate, path: []byte("/d/b.txt"), attr: attrToWire(Attr{Kind: File, Mode: 0o644})})

	r := rt(request{kind: rReadDir, path: []byte("/d")})
	if r.kind != pDir || len(r.dir) != 2 {
		t.Fatalf("readdir: %+v", r)
	}
	if string(r.dir[0].name) != "a.txt" || string(r.dir[1].name) != "b.txt" {
		t.Fatalf("readdir names: %q %q", r.dir[0].name, r.dir[1].name)
	}
}

//--------------------------------------------------------------------------------------------------
// Malformed-input hardening
//--------------------------------------------------------------------------------------------------

func TestDecodeRejectsOverflowingByteLength(t *testing.T) {
	// { "GetAttr": { "path": <byte string claiming 0x7fffffffffffffff bytes> } }
	buf := []byte{0xa1, 0x67}
	buf = append(buf, "GetAttr"...)
	buf = append(buf, 0xa1, 0x64)
	buf = append(buf, "path"...)
	buf = append(buf, 0x5b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // bytes, 8-byte len
	if _, err := decodeRequest(buf); err == nil {
		t.Fatal("expected error for overflowing byte-string length (must not panic)")
	}
}

func TestDecodeRejectsHugeArrayCount(t *testing.T) {
	// { "Dir": [array claiming 0x7fffffffffffffff elements] }
	buf := []byte{0xa1, 0x63}
	buf = append(buf, "Dir"...)
	buf = append(buf, 0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // array, 8-byte len
	if _, err := decodeResponse(buf); err == nil {
		t.Fatal("expected error for huge array count (must not panic/OOM)")
	}
}

func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	r := bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}) // 4 GiB length prefix
	if _, _, err := readFrame(r); err == nil {
		t.Fatal("expected error for oversized frame (must not allocate 4 GiB)")
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, maxFrameLen+1)
	if err := writeFrame(&bytes.Buffer{}, 1, payload); err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestDecodeGetAttrManyRejectsOversizedPathBytes(t *testing.T) {
	paths := [][]byte{bytes.Repeat([]byte("a"), maxBatchPathBytes+1)}
	reqBytes := encodeRequest(request{kind: rGetAttrMany, paths: paths})
	if _, err := decodeRequest(reqBytes); err == nil {
		t.Fatal("expected error for GetAttrMany path bytes over limit")
	}
}

func TestDecodeRequestRejectsOversizedWrite(t *testing.T) {
	reqBytes := encodeRequest(request{
		kind: rWrite,
		path: []byte("/a"),
		data: make([]byte, maxIOSize+1),
	})
	_, err := decodeRequest(reqBytes)
	if err == nil {
		t.Fatal("expected error for oversized write payload at decode time")
	}
	if errnoOf(err) != EINVAL {
		t.Fatalf("decode oversized write errno = %d, want %d (%v)", errnoOf(err), EINVAL, err)
	}
}

func TestDecodeRequestRejectsOversizedSymlinkTarget(t *testing.T) {
	reqBytes := encodeRequest(request{
		kind:   rSymlink,
		path:   []byte("/a"),
		target: bytes.Repeat([]byte("a"), maxSymlinkTarget+1),
	})
	_, err := decodeRequest(reqBytes)
	if err == nil {
		t.Fatal("expected error for oversized symlink target at decode time")
	}
	if errnoOf(err) != ENAMETOOLONG {
		t.Fatalf("decode oversized symlink errno = %d, want %d (%v)", errnoOf(err), ENAMETOOLONG, err)
	}
}

func TestErrnoOfTypedNil(t *testing.T) {
	var e *Errno
	if got := errnoOf(error(e)); got != EIO {
		t.Fatalf("typed-nil *Errno: got %d, want EIO", got)
	}
}

func TestServeReadOnlyDefaultsENOSYS(t *testing.T) {
	// memFs embeds ReadOnly and does not override Remove, so the mutation is
	// rejected with the ReadOnly default (ENOSYS).
	rt, cleanup := serveTest(t, newMemFs())
	defer cleanup()

	if r := rt(request{kind: rRemove, path: []byte("/x")}); r.kind != pErr || r.errno != ENOSYS {
		t.Fatalf("expected ENOSYS, got %+v", r)
	}
}

type memFsWithRemove struct {
	*memFs
}

func (f *memFsWithRemove) Remove(path []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := string(path)
	if _, ok := f.m[k]; !ok {
		return Err(ENOENT)
	}
	delete(f.m, k)
	return nil
}

func TestRemoveDirRejectsNonemptyChild(t *testing.T) {
	fs := &memFsWithRemove{memFs: newMemFs()}
	var cache readDirCache
	if _, err := fs.Mkdir([]byte("/d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if resp := dispatch(fs, request{
		kind: rCreate,
		path: []byte("/d/f"),
		attr: attrToWire(Attr{Kind: File, Mode: 0o644, Nlink: 1}),
	}, &cache); resp.kind != pAttr {
		t.Fatalf("create: %+v", resp)
	}
	if resp := dispatch(fs, request{kind: rRemove, path: []byte("/d")}, &cache); resp.kind != pErr || resp.errno != ENOTEMPTY {
		t.Fatalf("remove non-empty dir: %+v", resp)
	}
}

func TestReadDirRefetchesAfterMutationInvalidatesCache(t *testing.T) {
	fs := &memFsWithRemove{memFs: newMemFs()}
	var cache readDirCache
	if _, err := fs.Mkdir([]byte("/d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if resp := dispatch(fs, request{kind: rReadDir, path: []byte("/d")}, &cache); resp.kind != pDir || len(resp.dir) != 0 {
		t.Fatalf("initial readdir: %+v", resp)
	}
	if resp := dispatch(fs, request{
		kind: rCreate,
		path: []byte("/d/f"),
		attr: attrToWire(Attr{Kind: File, Mode: 0o644, Nlink: 1}),
	}, &cache); resp.kind != pAttr {
		t.Fatalf("create: %+v", resp)
	}
	if resp := dispatch(fs, request{kind: rReadDir, path: []byte("/d")}, &cache); resp.kind != pDir || len(resp.dir) != 1 || string(resp.dir[0].name) != "f" {
		t.Fatalf("post-create readdir should refetch, not serve cached empty listing: %+v", resp)
	}
}

func TestRemoveEmptyDirBeforeCreate(t *testing.T) {
	fs := &memFsWithRemove{memFs: newMemFs()}
	var cache readDirCache
	if _, err := fs.Mkdir([]byte("/d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if resp := dispatch(fs, request{kind: rRemove, path: []byte("/d")}, &cache); resp.kind != pOk {
		t.Fatalf("remove empty dir: %+v", resp)
	}
	if resp := dispatch(fs, request{
		kind: rCreate,
		path: []byte("/d/f"),
		attr: attrToWire(Attr{Kind: File, Mode: 0o644, Nlink: 1}),
	}, &cache); resp.kind != pErr || resp.errno != ENOENT {
		t.Fatalf("create after rmdir should fail: %+v", resp)
	}
}

func TestRemoveEmptyDirConcurrentCreate(t *testing.T) {
	fs := &memFsWithRemove{memFs: newMemFs()}
	if _, err := fs.Mkdir([]byte("/d"), 0o755); err != nil {
		t.Fatal(err)
	}
	var cache readDirCache
	for i := 0; i < 32; i++ {
		done := make(chan struct{}, 2)
		var removeResp, createResp response
		go func() {
			removeResp = dispatch(fs, request{kind: rRemove, path: []byte("/d")}, &cache)
			done <- struct{}{}
		}()
		go func() {
			createResp = dispatch(fs, request{
				kind: rCreate,
				path: []byte("/d/f"),
				attr: attrToWire(Attr{Kind: File, Mode: 0o644, Nlink: 1}),
			}, &cache)
			done <- struct{}{}
		}()
		<-done
		<-done

		_, dirErr := fs.GetAttr([]byte("/d"))
		_, childErr := fs.GetAttr([]byte("/d/f"))
		dirExists := dirErr == nil
		childExists := childErr == nil
		if dirExists && childExists {
			if createResp.kind != pAttr {
				t.Fatalf("iteration %d: create should win: remove=%+v create=%+v", i, removeResp, createResp)
			}
			if removeResp.kind != pErr || removeResp.errno != ENOTEMPTY {
				t.Fatalf("iteration %d: non-empty remove should be ENOTEMPTY: %+v", i, removeResp)
			}
		} else if !dirExists && !childExists {
			if removeResp.kind != pOk {
				t.Fatalf("iteration %d: removed dir should win: remove=%+v create=%+v", i, removeResp, createResp)
			}
		} else if dirExists && !childExists {
			if removeResp.kind != pOk {
				t.Fatalf("iteration %d: empty dir remove should succeed: %+v", i, removeResp)
			}
		} else {
			t.Fatalf("iteration %d: inconsistent tree remove=%+v create=%+v", i, removeResp, createResp)
		}

		if _, err := fs.GetAttr([]byte("/d/f")); err == nil {
			if resp := dispatch(fs, request{kind: rRemove, path: []byte("/d/f")}, &cache); resp.kind != pOk {
				t.Fatalf("cleanup remove /d/f: %+v", resp)
			}
		}
		if _, err := fs.GetAttr([]byte("/d")); err != nil {
			if _, err := fs.Mkdir([]byte("/d"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestServeConcurrentRequests(t *testing.T) {
	fs := &slowMemFs{memFs: newMemFs()}
	client, cleanup := serveTestMux(t, fs)
	defer cleanup()

	if r := client.call(request{kind: rMkdir, path: []byte("/d"), mode: 0o755}); r.kind != pAttr {
		t.Fatalf("mkdir: %+v", r)
	}
	if r := client.call(request{kind: rCreate, path: []byte("/d/f.txt"), attr: attrToWire(Attr{Kind: File, Mode: 0o644})}); r.kind != pAttr {
		t.Fatalf("create: %+v", r)
	}
	if r := client.call(request{kind: rWrite, path: []byte("/d/f.txt"), offset: 0, data: []byte("hello")}); r.kind != pCount {
		t.Fatalf("write: %+v", r)
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r := client.call(request{kind: rRead, path: []byte("/d/f.txt"), offset: 0, size: 1024}); r.kind != pBytes {
				errs <- fmt.Errorf("read: %+v", r)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if fs.maxConcurrent() < 2 {
		t.Fatalf("expected overlapping provider calls, max concurrent = %d", fs.maxConcurrent())
	}
}

type muxClient struct {
	conn      net.Conn
	writeMu   sync.Mutex
	nextID    uint64
	pendingMu sync.Mutex
	pending   map[uint64]chan response
}

func serveTestMux(t *testing.T, fs PathFs) (*muxClient, func()) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, fs) }()

	if err := writeHello(client); err != nil {
		t.Fatalf("writeHello: %v", err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatalf("readHello: %v", err)
	}

	mc := &muxClient{
		conn:    client,
		pending: make(map[uint64]chan response),
	}
	go mc.readLoop()

	cleanup := func() {
		client.Close()
		if err := <-done; err != nil && err != io.EOF {
			t.Errorf("Serve returned: %v", err)
		}
	}
	return mc, cleanup
}

func (c *muxClient) readLoop() {
	for {
		id, respBytes, err := readFrame(c.conn)
		if err != nil {
			return
		}
		resp, err := decodeResponse(respBytes)
		if err != nil {
			return
		}
		c.pendingMu.Lock()
		ch := c.pending[id]
		delete(c.pending, id)
		c.pendingMu.Unlock()
		if ch != nil {
			ch <- resp
		}
	}
}

func (c *muxClient) call(req request) response {
	c.pendingMu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan response, 1)
	c.pending[id] = ch
	c.pendingMu.Unlock()

	c.writeMu.Lock()
	err := writeFrame(c.conn, id, encodeRequest(req))
	c.writeMu.Unlock()
	if err != nil {
		return response{kind: pErr, errno: EIO}
	}
	return <-ch
}

type slowMemFs struct {
	*memFs
	mu          sync.Mutex
	inflight    int
	maxInflight int
}

func (f *slowMemFs) Create(path []byte, attr Attr) (Attr, error) {
	f.track()
	defer f.untrack()
	time.Sleep(5 * time.Millisecond)
	return f.memFs.Create(path, attr)
}

func (f *slowMemFs) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	f.track()
	defer f.untrack()
	time.Sleep(5 * time.Millisecond)
	return f.memFs.Read(path, offset, size)
}

func (f *slowMemFs) track() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inflight++
	if f.inflight > f.maxInflight {
		f.maxInflight = f.inflight
	}
}

func (f *slowMemFs) untrack() {
	f.mu.Lock()
	f.inflight--
	f.mu.Unlock()
}

func (f *slowMemFs) maxConcurrent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInflight
}

func TestDispatchRejectsInvalidOutboundNodeKind(t *testing.T) {
	fs := badKindFs{}
	resp := dispatch(fs, request{kind: rGetAttr, path: []byte("/x")}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EINVAL {
		t.Fatalf("invalid node kind: got kind=%d errno=%d", resp.kind, resp.errno)
	}
}

type badKindFs struct{ ReadOnly }

func (badKindFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: NodeKind(99)}, nil
}

func (badKindFs) ReadDir([]byte) ([]DirEntry, error) {
	return nil, Err(ENOENT)
}

func (badKindFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, Err(ENOENT)
}

func TestRenameWireRoundTripIncludesFlags(t *testing.T) {
	req := request{kind: rRename, from: []byte("/a"), to: []byte("/b"), flags: RenameNoReplace}
	raw := encodeRequest(req)
	got, err := decodeRequest(raw)
	if err != nil {
		t.Fatalf("decodeRequest: %v", err)
	}
	if got.flags != RenameNoReplace {
		t.Fatalf("flags = %d, want %d", got.flags, RenameNoReplace)
	}
}

func TestRenameNoReplaceAtomicViaRenameWithFlags(t *testing.T) {
	fs := newMemFs()
	if _, err := fs.Create([]byte("/src"), Attr{Kind: File, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Create([]byte("/dst"), Attr{Kind: File, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	resp := dispatch(fs, request{
		kind:  rRename,
		from:  []byte("/src"),
		to:    []byte("/dst"),
		flags: RenameNoReplace,
	}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EEXIST {
		t.Fatalf("RenameNoReplace: kind=%d errno=%d", resp.kind, resp.errno)
	}
}

func TestRenameNoReplaceFallbackSucceedsWhenDestinationMissing(t *testing.T) {
	fs := renameOnlyFs{mem: newMemFs()}
	if _, err := fs.mem.Create([]byte("/src"), Attr{Kind: File, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	resp := dispatch(fs, request{
		kind:  rRename,
		from:  []byte("/src"),
		to:    []byte("/dst"),
		flags: RenameNoReplace,
	}, &readDirCache{})
	if resp.kind != pOk {
		t.Fatalf("RenameNoReplace to missing dst: kind=%d errno=%d", resp.kind, resp.errno)
	}
	if _, err := fs.mem.GetAttr([]byte("/dst")); err != nil {
		t.Fatalf("expected /dst after rename: %v", err)
	}
}

type renameOnlyFs struct {
	ReadOnly
	mem *memFs
}

func (f renameOnlyFs) GetAttr(path []byte) (Attr, error) { return f.mem.GetAttr(path) }
func (f renameOnlyFs) ReadDir(path []byte) ([]DirEntry, error) { return f.mem.ReadDir(path) }
func (f renameOnlyFs) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	return f.mem.Read(path, offset, size)
}
func (f renameOnlyFs) Rename(from, to []byte) error { return f.mem.Rename(from, to) }
