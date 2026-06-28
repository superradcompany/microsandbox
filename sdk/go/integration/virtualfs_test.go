//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/superradcompany/microsandbox/sdk/go/vfs"
)

type memVfs struct {
	mu    sync.RWMutex
	files map[string][]byte
	dirs  map[string]struct{}
}

func newMemVfs(seed map[string]string) *memVfs {
	m := &memVfs{
		files: make(map[string][]byte),
		dirs: map[string]struct{}{
			"/": {},
		},
	}
	for path, content := range seed {
		m.files[path] = []byte(content)
	}
	return m
}

func (m *memVfs) GetAttr(path []byte) (vfs.Attr, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := string(path)
	if _, ok := m.dirs[p]; ok {
		return vfs.Attr{Kind: vfs.Dir, Mode: 0o755}, nil
	}
	data, ok := m.files[p]
	if !ok {
		return vfs.Attr{}, vfs.Err(vfs.ENOENT)
	}
	return vfs.Attr{Kind: vfs.File, Mode: 0o644, Size: uint64(len(data))}, nil
}

func (m *memVfs) ReadDir(path []byte) ([]vfs.DirEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := string(path)
	if _, ok := m.dirs[p]; !ok {
		if _, file := m.files[p]; file {
			return nil, vfs.Err(vfs.ENOTDIR)
		}
		return nil, vfs.Err(vfs.ENOENT)
	}
	var out []vfs.DirEntry
	prefix := strings.TrimSuffix(p, "/") + "/"
	for filePath := range m.files {
		if !strings.HasPrefix(filePath, prefix) {
			continue
		}
		rest := strings.TrimPrefix(filePath, prefix)
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		out = append(out, vfs.DirEntry{Name: []byte(rest), Kind: vfs.File})
	}
	for dirPath := range m.dirs {
		if dirPath == p {
			continue
		}
		if !strings.HasPrefix(dirPath, prefix) {
			continue
		}
		rest := strings.TrimPrefix(dirPath, prefix)
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		out = append(out, vfs.DirEntry{Name: []byte(rest), Kind: vfs.Dir})
	}
	return out, nil
}

func (m *memVfs) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.files[string(path)]
	if !ok {
		return nil, vfs.Err(vfs.ENOENT)
	}
	if offset >= uint64(len(data)) {
		return nil, nil
	}
	end := int(offset) + int(size)
	if end > len(data) {
		end = len(data)
	}
	out := make([]byte, end-int(offset))
	copy(out, data[offset:end])
	return out, nil
}

func (m *memVfs) Write(path []byte, offset uint64, data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := string(path)
	cur := m.files[p]
	if offset > uint64(len(cur)) {
		grow := make([]byte, offset)
		copy(grow, cur)
		cur = grow
	}
	end := int(offset) + len(data)
	if end > len(cur) {
		grow := make([]byte, end)
		copy(grow, cur)
		cur = grow
	}
	copy(cur[offset:], data)
	m.files[p] = cur
	return len(data), nil
}

func (m *memVfs) Create(path []byte, attr vfs.Attr) (vfs.Attr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := string(path)
	if _, ok := m.files[p]; ok {
		return vfs.Attr{}, vfs.Err(vfs.EEXIST)
	}
	if _, ok := m.dirs[p]; ok {
		return vfs.Attr{}, vfs.Err(vfs.EEXIST)
	}
	switch attr.Kind {
	case vfs.Dir:
		m.dirs[p] = struct{}{}
		return vfs.Attr{Kind: vfs.Dir, Mode: attr.Mode}, nil
	default:
		m.files[p] = nil
		return vfs.Attr{Kind: vfs.File, Mode: attr.Mode}, nil
	}
}

func (m *memVfs) Mkdir(path []byte, mode uint32) (vfs.Attr, error) {
	return m.Create(path, vfs.Attr{Kind: vfs.Dir, Mode: mode})
}

func (m *memVfs) Remove(path []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := string(path)
	if _, ok := m.dirs[p]; ok {
		delete(m.dirs, p)
		return nil
	}
	if _, ok := m.files[p]; ok {
		delete(m.files, p)
		return nil
	}
	return vfs.Err(vfs.ENOENT)
}

func (m *memVfs) Rename(from, to []byte) error {
	return m.RenameWithFlags(from, to, 0)
}

func (m *memVfs) RenameWithFlags(from, to []byte, flags uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fromP, toP := string(from), string(to)
	_, fileOK := m.files[fromP]
	_, dirOK := m.dirs[fromP]
	if !fileOK && !dirOK {
		return vfs.Err(vfs.ENOENT)
	}
	if flags&vfs.RenameNoReplace != 0 && fromP != toP {
		if _, ok := m.files[toP]; ok {
			return vfs.Err(vfs.EEXIST)
		}
		if _, ok := m.dirs[toP]; ok {
			return vfs.Err(vfs.EEXIST)
		}
	}
	if _, ok := m.files[toP]; ok {
		return vfs.Err(vfs.EEXIST)
	}
	if _, ok := m.dirs[toP]; ok {
		return vfs.Err(vfs.EEXIST)
	}
	if fileOK {
		m.files[toP] = m.files[fromP]
		delete(m.files, fromP)
	} else {
		m.dirs[toP] = struct{}{}
		delete(m.dirs, fromP)
	}
	return nil
}

func (m *memVfs) SetAttr(path []byte, attr vfs.Attr, valid vfs.SetAttrValid) (vfs.Attr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := string(path)
	if _, ok := m.dirs[p]; ok {
		if valid.Has(vfs.SetMode) {
			return vfs.Attr{Kind: vfs.Dir, Mode: attr.Mode}, nil
		}
		return vfs.Attr{Kind: vfs.Dir, Mode: 0o755}, nil
	}
	data, ok := m.files[p]
	if !ok {
		return vfs.Attr{}, vfs.Err(vfs.ENOENT)
	}
	if valid.Has(vfs.SetSize) && attr.Size < uint64(len(data)) {
		data = data[:attr.Size]
		m.files[p] = data
	}
	return vfs.Attr{Kind: vfs.File, Mode: 0o644, Size: uint64(len(data))}, nil
}

func (m *memVfs) Symlink(path, target []byte) (vfs.Attr, error) {
	return vfs.Attr{}, vfs.Err(vfs.ENOSYS)
}

func (m *memVfs) ReadLink(path []byte) ([]byte, error) {
	return nil, vfs.Err(vfs.ENOSYS)
}

func (m *memVfs) SetXattr(path, name, value []byte, flags uint32) error {
	return vfs.Err(vfs.ENOSYS)
}

func (m *memVfs) GetXattr(path, name []byte) ([]byte, error) {
	return nil, vfs.Err(vfs.ENOSYS)
}

func (m *memVfs) ListXattr(path []byte) ([][]byte, error) {
	return nil, vfs.Err(vfs.ENOSYS)
}

func (m *memVfs) RemoveXattr(path, name []byte) error {
	return vfs.Err(vfs.ENOSYS)
}

func (m *memVfs) Flush(path []byte) error {
	return nil
}

func (m *memVfs) Fsync(path []byte, datasync bool) error {
	return nil
}

func (m *memVfs) StatFs() (vfs.StatFs, error) {
	return vfs.StatFs{}, nil
}

func (m *memVfs) addFileOutOfBand(path string, content []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = append([]byte(nil), content...)
}

func TestVirtualMountReadWrite(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-virtualfs-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	provider := newMemVfs(map[string]string{
		"/hello.txt": "from-go-provider",
	})

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithVirtualMount("/inbox", provider),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "cat /inbox/hello.txt")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if got := strings.TrimSpace(out.Stdout()); got != "from-go-provider" {
		t.Fatalf("cat stdout = %q, want %q", got, "from-go-provider")
	}

	writeOut, err := sb.Shell(ctx, "sh -c 'echo guest-write > /inbox/written.txt'")
	if err != nil {
		t.Fatalf("write shell: %v", err)
	}
	if !writeOut.Success() {
		t.Fatalf("write shell failed: %s", writeOut.Stderr())
	}

	provider.mu.RLock()
	got := string(provider.files["/written.txt"])
	provider.mu.RUnlock()
	if strings.TrimSpace(got) != "guest-write" {
		t.Fatalf("provider file = %q, want %q", got, "guest-write")
	}

	listOut, err := sb.Shell(ctx, "ls /inbox")
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	if !strings.Contains(listOut.Stdout(), "hello.txt") || !strings.Contains(listOut.Stdout(), "written.txt") {
		t.Fatalf("ls /inbox = %q", listOut.Stdout())
	}
}

// TestVirtualMountWithReplace verifies that replacing a same-name sandbox with
// virtual mounts leaves the new provider serving and does not tear down the
// replacement when the prior handle requests stop.
func TestVirtualMountWithReplace(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-virtualfs-replace-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))

	firstProvider := newMemVfs(map[string]string{
		"/first.txt": "first",
	})
	sb1, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithVirtualMount("/inbox", firstProvider),
	)
	if err != nil {
		t.Fatalf("CreateSandbox first: %v", err)
	}

	secondProvider := newMemVfs(map[string]string{
		"/second.txt": "second",
	})
	sb2, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithReplace(),
		microsandbox.WithVirtualMount("/inbox", secondProvider),
	)
	if err != nil {
		t.Fatalf("CreateSandbox with replace: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb2.Stop(stopCtx)
		_ = sb2.Close()
	})

	// Deferred teardown on the replaced handle must not kill the new provider.
	if err := sb1.RequestStop(context.Background()); err != nil {
		t.Fatalf("RequestStop on replaced handle: %v", err)
	}
	_ = sb1.Close()

	out, err := sb2.Shell(ctx, "cat /inbox/second.txt")
	if err != nil {
		t.Fatalf("Shell after replace: %v", err)
	}
	if got := strings.TrimSpace(out.Stdout()); got != "second" {
		t.Fatalf("cat stdout = %q, want %q", got, "second")
	}
}

func TestVirtualMountFsyncDirRefreshesOutOfBandListing(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-virtualfs-fsyncdir-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	provider := newMemVfs(map[string]string{
		"/hello.txt": "seed",
	})

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithReplace(),
		microsandbox.WithVirtualMount("/inbox", provider),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	installOut, err := sb.Shell(ctx, "apk add --quiet --no-progress util-linux >/dev/null 2>&1")
	if err != nil {
		t.Fatalf("install util-linux: %v", err)
	}
	if !installOut.Success() {
		t.Fatalf("install util-linux failed: %s", installOut.Stderr())
	}

	initial, err := sb.Shell(ctx, "ls /inbox")
	if err != nil {
		t.Fatalf("initial ls: %v", err)
	}
	if !initial.Success() {
		t.Fatalf("initial ls failed: %s", initial.Stderr())
	}
	if !strings.Contains(initial.Stdout(), "hello.txt") {
		t.Fatalf("initial ls = %q, want hello.txt", initial.Stdout())
	}
	if strings.Contains(initial.Stdout(), "fresh.txt") {
		t.Fatalf("fresh.txt should not exist yet: %q", initial.Stdout())
	}

	provider.addFileOutOfBand("/fresh.txt", []byte("out-of-band"))

	stale, err := sb.Shell(ctx, "ls /inbox")
	if err != nil {
		t.Fatalf("stale ls: %v", err)
	}
	if !stale.Success() {
		t.Fatalf("stale ls failed: %s", stale.Stderr())
	}
	if strings.Contains(stale.Stdout(), "fresh.txt") {
		t.Fatalf("listing should stay stale before fsyncdir: %q", stale.Stdout())
	}

	syncOut, err := sb.Shell(ctx, "sync -f /inbox")
	if err != nil {
		t.Fatalf("sync -f /inbox: %v", err)
	}
	if !syncOut.Success() {
		t.Fatalf("sync -f /inbox failed: %s", syncOut.Stderr())
	}

	refreshed, err := sb.Shell(ctx, "ls /inbox")
	if err != nil {
		t.Fatalf("refreshed ls: %v", err)
	}
	if !refreshed.Success() {
		t.Fatalf("refreshed ls failed: %s", refreshed.Stderr())
	}
	if !strings.Contains(refreshed.Stdout(), "hello.txt") {
		t.Fatalf("refreshed ls missing hello.txt: %q", refreshed.Stdout())
	}
	if !strings.Contains(refreshed.Stdout(), "fresh.txt") {
		t.Fatalf("fsyncdir should expose out-of-band listing change: %q", refreshed.Stdout())
	}
}
