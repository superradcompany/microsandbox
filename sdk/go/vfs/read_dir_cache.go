package vfs

import (
	"sync"
)

// readDirCache holds the last full directory listing per path on a connection so
// paginated ReadDir RPCs do not re-query the provider on every page. Invalidated
// after a successful mutating op on this connection; a generation counter forces
// a refetch when pagination continues after an overlapping mutation. At most
// maxReaddirCachePaths distinct paths are retained per connection.
type readDirCache struct {
	mu         sync.Mutex
	mutationMu sync.Mutex
	generation uint64
	dirs       map[string]*dirCacheEntry
	dirOrder   []string
	inflight   map[string]*inflightReadDir
}

type dirCacheEntry struct {
	entries           []DirEntry
	fetchedGeneration uint64
}

type inflightReadDir struct {
	done chan struct{}
}

func (c *readDirCache) invalidate() {
	c.mu.Lock()
	c.generation++
	c.dirs = nil
	c.dirOrder = nil
	c.finishAllInflightLocked()
	c.mu.Unlock()
}

func (c *readDirCache) page(fs PathFs, path []byte, offset uint64, limit int) ([]DirEntry, error) {
	for attempt := 0; attempt < maxReaddirFetchRetries; attempt++ {
		if page, ok, err := c.pageFromCache(path, offset, limit); ok {
			return page, err
		}

		wait, fetchGen, shouldFetch, infl := c.beginFetch(path)
		if wait != nil {
			<-wait
			continue
		}
		if !shouldFetch {
			continue
		}

		page, ok, err := c.fetchAndStore(fs, path, fetchGen, infl, offset, limit)
		if ok {
			return page, err
		}
	}
	return nil, Err(EAGAIN)
}

func (c *readDirCache) fetchAndStore(
	fs PathFs,
	path []byte,
	fetchGen uint64,
	infl *inflightReadDir,
	offset uint64,
	limit int,
) ([]DirEntry, bool, error) {
	defer c.finishInflight(path, infl)

	entries, err := fs.ReadDir(path)
	if err != nil {
		return nil, true, err
	}
	filtered := make([]DirEntry, 0, len(entries))
	for _, de := range entries {
		if validateReaddirName(de.Name) != nil {
			logFilteredReaddirName(de.Name)
			continue
		}
		if validateNodeKind(de.Kind) != nil {
			logFilteredReaddirKind(de.Kind)
			continue
		}
		filtered = append(filtered, de)
	}
	if len(filtered) > maxReaddirTotal {
		return nil, true, Err(EINVAL)
	}
	return c.storeFetch(path, fetchGen, filtered, offset, limit)
}

func (c *readDirCache) pageFromCache(path []byte, offset uint64, limit int) ([]DirEntry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := string(path)
	ent := c.cachedEntryLocked(key)
	if offset > 0 {
		if ent == nil {
			return nil, true, Err(EAGAIN)
		}
		off := int(offset)
		if off > len(ent.entries) {
			return nil, true, nil
		}
		end := off + limit
		if end > len(ent.entries) {
			end = len(ent.entries)
		}
		c.touchDirLocked(key)
		return append([]DirEntry(nil), ent.entries[off:end]...), true, nil
	}
	if ent == nil {
		return nil, false, nil
	}
	end := limit
	if end > len(ent.entries) {
		end = len(ent.entries)
	}
	c.touchDirLocked(key)
	return append([]DirEntry(nil), ent.entries[:end]...), true, nil
}

func (c *readDirCache) beginFetch(path []byte) (wait <-chan struct{}, fetchGen uint64, shouldFetch bool, infl *inflightReadDir) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := string(path)
	if c.inflight == nil {
		c.inflight = make(map[string]*inflightReadDir)
	}
	if c.cachedEntryLocked(key) != nil {
		return nil, 0, false, nil
	}
	if existing := c.inflight[key]; existing != nil {
		return existing.done, 0, false, nil
	}
	fetchGen = c.generation
	infl = &inflightReadDir{done: make(chan struct{})}
	c.inflight[key] = infl
	return nil, fetchGen, true, infl
}

func (c *readDirCache) finishInflight(path []byte, infl *inflightReadDir) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finishInflightEntryLocked(path, infl)
}

// finishAllInflightLocked closes every inflight waiter. Caller must hold c.mu.
func (c *readDirCache) finishAllInflightLocked() {
	if c.inflight == nil {
		return
	}
	for key, existing := range c.inflight {
		close(existing.done)
		delete(c.inflight, key)
	}
}

// finishInflightEntryLocked closes one inflight waiter when infl is still
// registered for path. Caller must hold c.mu.
func (c *readDirCache) finishInflightEntryLocked(path []byte, infl *inflightReadDir) {
	if c.inflight == nil {
		return
	}
	key := string(path)
	if existing, ok := c.inflight[key]; ok && existing == infl {
		close(existing.done)
		delete(c.inflight, key)
	}
}

func (c *readDirCache) storeFetch(
	path []byte,
	fetchGen uint64,
	filtered []DirEntry,
	offset uint64,
	limit int,
) ([]DirEntry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != fetchGen {
		return nil, false, nil
	}
	key := string(path)
	if c.dirs == nil {
		c.dirs = make(map[string]*dirCacheEntry)
	}
	ent := c.dirs[key]
	if ent == nil {
		ent = &dirCacheEntry{}
		c.dirs[key] = ent
	}
	ent.entries = filtered
	ent.fetchedGeneration = c.generation
	c.touchDirLocked(key)
	c.evictDirsLocked()
	off := int(offset)
	if off > len(ent.entries) {
		return nil, true, nil
	}
	end := off + limit
	if end > len(ent.entries) {
		end = len(ent.entries)
	}
	return append([]DirEntry(nil), ent.entries[off:end]...), true, nil
}

func (c *readDirCache) cachedEntryLocked(key string) *dirCacheEntry {
	if c.dirs == nil {
		return nil
	}
	ent := c.dirs[key]
	if ent == nil || ent.fetchedGeneration != c.generation {
		return nil
	}
	return ent
}

func (c *readDirCache) touchDirLocked(key string) {
	for i, k := range c.dirOrder {
		if k == key {
			c.dirOrder = append(append(c.dirOrder[:i], c.dirOrder[i+1:]...), key)
			return
		}
	}
	c.dirOrder = append(c.dirOrder, key)
}

func (c *readDirCache) evictDirsLocked() {
	for len(c.dirs) > maxReaddirCachePaths {
		if len(c.dirOrder) == 0 {
			return
		}
		evict := c.dirOrder[0]
		c.dirOrder = c.dirOrder[1:]
		delete(c.dirs, evict)
	}
}

func invalidatesReadDirCache(kind reqKind) bool {
	switch kind {
	case rWrite, rCreate, rMkdir, rRemove, rRename, rSetAttr,
		rSymlink, rSetXattr, rRemoveXattr, rFsyncDir:
		return true
	default:
		return false
	}
}
