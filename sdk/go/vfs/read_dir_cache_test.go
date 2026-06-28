package vfs

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type mutableDirFs struct {
	ReadOnly
	mu      sync.Mutex
	entries map[string][]DirEntry
}

func (f *mutableDirFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: Dir, Mode: 0o755, Nlink: 2}, nil
}

func (f *mutableDirFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, nil
}

func (f *mutableDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DirEntry(nil), f.entries[string(path)]...), nil
}

func (f *mutableDirFs) Write([]byte, uint64, []byte) (int, error) {
	return 1, nil
}

type writeErrFs struct {
	mutableDirFs
}

func (writeErrFs) Write([]byte, uint64, []byte) (int, error) {
	return 0, Err(EPERM)
}

func TestReadDirCacheInvalidatedAfterSuccessfulWrite(t *testing.T) {
	fs := &mutableDirFs{
		entries: map[string][]DirEntry{
			"/": {{Name: []byte("a"), Kind: File}},
		},
	}
	cache := &readDirCache{}

	first, err := cache.page(fs, []byte("/"), 0, 64)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first) != 1 || string(first[0].Name) != "a" {
		t.Fatalf("first page = %+v, want [a]", first)
	}

	fs.entries["/"] = []DirEntry{{Name: []byte("b"), Kind: File}}

	resp := dispatch(fs, request{kind: rWrite, path: []byte("/a"), data: []byte("x")}, cache)
	if resp.kind == pErr {
		t.Fatalf("write failed: errno %d", resp.errno)
	}

	second, err := cache.page(fs, []byte("/"), 0, 64)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second) != 1 || string(second[0].Name) != "b" {
		t.Fatalf("second page = %+v, want [b] after write invalidated cache", second)
	}
}

func TestReadDirCacheNotInvalidatedAfterFailedWrite(t *testing.T) {
	fs := &writeErrFs{
		mutableDirFs: mutableDirFs{
			entries: map[string][]DirEntry{
				"/": {{Name: []byte("a"), Kind: File}},
			},
		},
	}
	cache := &readDirCache{}
	if _, err := cache.page(fs, []byte("/"), 0, 64); err != nil {
		t.Fatalf("page: %v", err)
	}

	fs.entries["/"] = []DirEntry{{Name: []byte("b"), Kind: File}}

	resp := dispatch(fs, request{kind: rWrite, path: []byte("/a"), data: []byte("x")}, cache)
	if resp.kind != pErr {
		t.Fatalf("write should fail, got %+v", resp)
	}

	second, err := cache.page(fs, []byte("/"), 0, 64)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second) != 1 || string(second[0].Name) != "a" {
		t.Fatalf("second page = %+v, want cached [a] after failed write", second)
	}
}

func TestReadDirCacheReturnsEagainWhenInvalidatedBetweenPages(t *testing.T) {
	fs := &mutableDirFs{
		entries: map[string][]DirEntry{
			"/": {
				{Name: []byte("a"), Kind: File},
				{Name: []byte("b"), Kind: File},
			},
		},
	}
	cache := &readDirCache{}

	first, err := cache.page(fs, []byte("/"), 0, 1)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first) != 1 || string(first[0].Name) != "a" {
		t.Fatalf("first page = %+v, want [a]", first)
	}

	fs.entries["/"] = []DirEntry{
		{Name: []byte("c"), Kind: File},
		{Name: []byte("d"), Kind: File},
	}
	resp := dispatch(fs, request{kind: rWrite, path: []byte("/a"), data: []byte("x")}, cache)
	if resp.kind == pErr {
		t.Fatalf("write failed: errno %d", resp.errno)
	}

	_, err = cache.page(fs, []byte("/"), 1, 64)
	if err == nil {
		t.Fatal("expected EAGAIN when continuing pagination after invalidation")
	}
	if errnoOf(err) != EAGAIN {
		t.Fatalf("expected EAGAIN, got %v", err)
	}
}

func TestReadDirCacheInvalidatedAfterFsyncDir(t *testing.T) {
	fs := &mutableDirFs{
		entries: map[string][]DirEntry{
			"/d": {{Name: []byte("a"), Kind: File}},
		},
	}
	cache := &readDirCache{}

	first, err := cache.page(fs, []byte("/d"), 0, 64)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first) != 1 || string(first[0].Name) != "a" {
		t.Fatalf("first page = %+v, want [a]", first)
	}

	fs.entries["/d"] = []DirEntry{
		{Name: []byte("a"), Kind: File},
		{Name: []byte("b"), Kind: File},
	}
	resp := dispatch(fs, request{kind: rFsyncDir, path: []byte("/d")}, cache)
	if resp.kind == pErr {
		t.Fatalf("fsyncdir failed: errno %d", resp.errno)
	}

	second, err := cache.page(fs, []byte("/d"), 0, 64)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second) != 2 {
		t.Fatalf("second page = %+v, want refreshed [a b]", second)
	}
}

func TestReadDirCacheDoesNotHoldLockDuringProviderReadDir(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fs := &blockingDirFs{
		entries: []DirEntry{{Name: []byte("a"), Kind: File}},
		started: started,
		unblock: make(chan struct{}),
	}
	cache := &readDirCache{}

	go func() {
		_, err := cache.page(fs, []byte("/"), 0, 64)
		close(release)
		if err != nil {
			t.Errorf("page: %v", err)
		}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ReadDir to start")
	}

	done := make(chan struct{})
	go func() {
		_, err := cache.page(fs, []byte("/other"), 0, 64)
		if err != nil {
			t.Errorf("concurrent page: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("second page blocked while first ReadDir was in flight")
	}

	close(fs.unblock)
	<-release
}

func TestReadDirCacheSingleFlightsConcurrentOffsetZeroFetch(t *testing.T) {
	fs := &countingDirFs{
		entries: []DirEntry{{Name: []byte("a"), Kind: File}},
	}
	cache := &readDirCache{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.page(fs, []byte("/"), 0, 64); err != nil {
				t.Errorf("page: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := fs.readDirCalls(); got != 1 {
		t.Fatalf("ReadDir calls = %d, want 1 (single-flight refetch)", got)
	}
}

func TestReadDirCacheSingleFlightsPerPathConcurrently(t *testing.T) {
	fs := &pathCountingDirFs{
		entries: map[string][]DirEntry{
			"/":      {{Name: []byte("a"), Kind: File}},
			"/other": {{Name: []byte("b"), Kind: File}},
		},
	}
	cache := &readDirCache{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := cache.page(fs, []byte("/"), 0, 64); err != nil {
				t.Errorf("page /: %v", err)
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := cache.page(fs, []byte("/other"), 0, 64); err != nil {
				t.Errorf("page /other: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := fs.readDirCalls("/"); got != 1 {
		t.Fatalf("ReadDir / calls = %d, want 1", got)
	}
	if got := fs.readDirCalls("/other"); got != 1 {
		t.Fatalf("ReadDir /other calls = %d, want 1", got)
	}
}

func TestReadDirCacheFinishesInflightOnOversizedListing(t *testing.T) {
	entries := make([]DirEntry, maxReaddirTotal+1)
	for i := range entries {
		entries[i] = DirEntry{Name: []byte("x"), Kind: File}
	}
	fs := &mutableDirFs{entries: map[string][]DirEntry{"/": entries}}
	cache := &readDirCache{}
	_, err := cache.page(fs, []byte("/"), 0, 64)
	if err == nil || errnoOf(err) != EINVAL {
		t.Fatalf("oversized listing = %v, want Err(EINVAL)", err)
	}
	done := make(chan struct{})
	go func() {
		_, err := cache.page(fs, []byte("/"), 0, 64)
		if err == nil {
			t.Error("expected error on second oversized listing attempt")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("page hung after oversized listing rejection")
	}
}

func TestReadDirCacheInvalidateUnblocksInflightWaiters(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fs := &blockingDirFs{
		entries: []DirEntry{{Name: []byte("a"), Kind: File}},
		started: started,
		unblock: make(chan struct{}),
	}
	cache := &readDirCache{}
	go func() {
		_, _ = cache.page(fs, []byte("/"), 0, 64)
		close(release)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ReadDir to start")
	}
	waiterDone := make(chan struct{})
	go func() {
		_, err := cache.page(fs, []byte("/"), 0, 64)
		if err != nil {
			t.Errorf("waiter page: %v", err)
		}
		close(waiterDone)
	}()
	time.Sleep(20 * time.Millisecond)
	cache.invalidate()
	close(fs.unblock)
	select {
	case <-waiterDone:
	case <-time.After(time.Second):
		t.Fatal("waiter blocked after invalidate during inflight fetch")
	}
	<-release
}

func TestReadDirCacheFinishesInflightOnReaddirError(t *testing.T) {
	fs := &errOnceDirFs{
		entries: []DirEntry{{Name: []byte("a"), Kind: File}},
	}
	cache := &readDirCache{}
	_, err := cache.page(fs, []byte("/"), 0, 64)
	if err == nil || errnoOf(err) != EIO {
		t.Fatalf("first page = %v, want Err(EIO)", err)
	}
	if _, err := cache.page(fs, []byte("/"), 0, 64); err != nil {
		t.Fatalf("second page after readdir error: %v", err)
	}
	if got := fs.readDirCalls(); got != 2 {
		t.Fatalf("ReadDir calls = %d, want 2", got)
	}
}

func TestReadDirCacheEvictsOldestPathBeyondLimit(t *testing.T) {
	fs := &pathCountingDirFs{entries: map[string][]DirEntry{}}
	cache := &readDirCache{}
	for i := range maxReaddirCachePaths {
		path := fmt.Sprintf("/dir%d", i)
		fs.entries[path] = nil
		if _, err := cache.page(fs, []byte(path), 0, 64); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	if got := fs.readDirCalls("/dir0"); got != 1 {
		t.Fatalf("initial /dir0 calls = %d, want 1", got)
	}
	overflow := fmt.Sprintf("/dir%d", maxReaddirCachePaths)
	fs.entries[overflow] = nil
	if _, err := cache.page(fs, []byte(overflow), 0, 64); err != nil {
		t.Fatalf("overflow path: %v", err)
	}
	if _, err := cache.page(fs, []byte("/dir0"), 0, 64); err != nil {
		t.Fatalf("refetch /dir0: %v", err)
	}
	if got := fs.readDirCalls("/dir0"); got != 2 {
		t.Fatalf("/dir0 calls after eviction = %d, want 2", got)
	}
}

type errOnceDirFs struct {
	ReadOnly
	mu        sync.Mutex
	entries   []DirEntry
	readDirN  int
}

func (f *errOnceDirFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: Dir, Mode: 0o755, Nlink: 2}, nil
}

func (f *errOnceDirFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, nil
}

func (f *errOnceDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readDirN++
	if f.readDirN == 1 {
		return nil, Err(EIO)
	}
	return append([]DirEntry(nil), f.entries...), nil
}

func (f *errOnceDirFs) readDirCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readDirN
}

type pathCountingDirFs struct {
	ReadOnly
	mu      sync.Mutex
	entries map[string][]DirEntry
	calls   map[string]int
}

func (f *pathCountingDirFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: Dir, Mode: 0o755, Nlink: 2}, nil
}

func (f *pathCountingDirFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, nil
}

func (f *pathCountingDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[string(path)]++
	return append([]DirEntry(nil), f.entries[string(path)]...), nil
}

func (f *pathCountingDirFs) readDirCalls(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

type countingDirFs struct {
	ReadOnly
	mu         sync.Mutex
	entries    []DirEntry
	readDirN   int
}

func (f *countingDirFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: Dir, Mode: 0o755, Nlink: 2}, nil
}

func (f *countingDirFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, nil
}

func (f *countingDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readDirN++
	return append([]DirEntry(nil), f.entries...), nil
}

func (f *countingDirFs) readDirCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readDirN
}

type blockingDirFs struct {
	ReadOnly
	entries []DirEntry
	started chan struct{}
	unblock chan struct{}
}

func (f *blockingDirFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: Dir, Mode: 0o755, Nlink: 2}, nil
}

func (f *blockingDirFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, nil
}

func (f *blockingDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	if string(path) == "/" {
		select {
		case f.started <- struct{}{}:
		default:
		}
		<-f.unblock
	}
	return append([]DirEntry(nil), f.entries...), nil
}

func TestReadDirCacheFiltersInvalidKindsBeforePagination(t *testing.T) {
	entries := make([]DirEntry, 0, 120)
	for i := range 100 {
		entries = append(entries, DirEntry{
			Name: []byte(fmt.Sprintf("f%03d", i)),
			Kind: File,
		})
		if i%10 == 0 {
			entries = append(entries, DirEntry{
				Name: []byte(fmt.Sprintf("bad%03d", i)),
				Kind: NodeKind(99),
			})
		}
	}
	fs := &countingDirFs{entries: entries}
	cache := &readDirCache{}
	limit := 32
	var got []DirEntry
	offset := uint64(0)
	for {
		page, err := cache.page(fs, []byte("/"), offset, limit)
		if err != nil {
			t.Fatalf("page at offset %d: %v", offset, err)
		}
		got = append(got, page...)
		if len(page) < limit {
			break
		}
		offset += uint64(len(page))
	}
	want := 100
	if len(got) != want {
		t.Fatalf("paginated entries = %d, want %d", len(got), want)
	}
	for i, de := range got {
		if validateNodeKind(de.Kind) != nil {
			t.Fatalf("entry %d has invalid kind %d", i, de.Kind)
		}
	}
}

type panicOnceDirFs struct {
	ReadOnly
	mu       sync.Mutex
	entries  []DirEntry
	readDirN int
}

func (f *panicOnceDirFs) GetAttr([]byte) (Attr, error) {
	return Attr{Kind: Dir, Mode: 0o755, Nlink: 2}, nil
}

func (f *panicOnceDirFs) Read([]byte, uint64, uint32) ([]byte, error) {
	return nil, nil
}

func (f *panicOnceDirFs) ReadDir(path []byte) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readDirN++
	if f.readDirN == 1 {
		panic("provider bug")
	}
	return append([]DirEntry(nil), f.entries...), nil
}

func TestReadDirCacheFinishesInflightOnProviderPanic(t *testing.T) {
	fs := &panicOnceDirFs{
		entries: []DirEntry{{Name: []byte("a"), Kind: File}},
	}
	cache := &readDirCache{}
	func() {
		defer func() { _ = recover() }()
		_, _ = cache.page(fs, []byte("/"), 0, 64)
	}()
	done := make(chan error, 1)
	go func() {
		_, err := cache.page(fs, []byte("/"), 0, 64)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second page after panic: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter blocked after provider panic during readdir")
	}
}
