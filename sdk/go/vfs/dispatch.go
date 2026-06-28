package vfs

// dispatch routes one decoded request to the provider and builds the response.
func dispatch(fs PathFs, r request, cache *readDirCache) response {
	if err := validateProviderPathForRequest(r); err != nil {
		return errResp(err)
	}
	// Serialize ReadDir against cache invalidation and membership mutations on
	// this connection so paginated listings cannot observe pre-mutation cache
	// entries (including at offset 0).
	if r.kind == rReadDir || invalidatesReadDirCache(r.kind) {
		cache.mutationMu.Lock()
		resp := dispatchOp(fs, r, cache)
		if invalidatesReadDirCache(r.kind) && resp.kind != pErr {
			cache.invalidate()
		}
		cache.mutationMu.Unlock()
		return resp
	}
	return dispatchOp(fs, r, cache)
}

func dispatchOp(fs PathFs, r request, cache *readDirCache) response {
	switch r.kind {
	case rGetAttr:
		a, err := fs.GetAttr(r.path)
		if err != nil {
			return errResp(err)
		}
		w, err := wireAttrFrom(a)
		if err != nil {
			return errResp(err)
		}
		return response{kind: pAttr, attr: w}

	case rGetAttrMany:
		if len(r.paths) > maxBatchPaths {
			return errResp(Err(EINVAL))
		}
		// Per-path failures are reported in-band so one bad entry does not fail
		// the whole batch.
		results := make([]attrResult, len(r.paths))
		for i, p := range r.paths {
			a, err := fs.GetAttr(p)
			if err != nil {
				results[i] = attrResult{errno: int32(errnoOf(err))}
				continue
			}
			w, werr := wireAttrFrom(a)
			if werr != nil {
				results[i] = attrResult{errno: int32(errnoOf(werr))}
				continue
			}
			results[i] = attrResult{ok: true, attr: w}
		}
		return response{kind: pAttrMany, attrMany: results}

	case rReadDir:
		limit := int(r.size)
		if limit == 0 || limit > maxReaddirEntries {
			limit = maxReaddirEntries
		}
		entries, err := cache.page(fs, r.path, r.offset, limit)
		if err != nil {
			return errResp(err)
		}
		dir := make([]dirEntryWire, len(entries))
		for i, de := range entries {
			dir[i] = dirEntryWire{name: de.Name, kind: uint8(de.Kind)}
		}
		return response{kind: pDir, dir: dir}

	case rReadLink:
		b, err := fs.ReadLink(r.path)
		if err != nil {
			return errResp(err)
		}
		if err := validateSymlinkTarget(b); err != nil {
			return errResp(err)
		}
		return response{kind: pBytes, data: b}

	case rRead:
		size := r.size
		if size > maxIOSize {
			return errResp(Err(EINVAL))
		}
		b, err := fs.Read(r.path, r.offset, size)
		if err != nil {
			return errResp(err)
		}
		if len(b) > int(size) {
			return errResp(Err(EIO))
		}
		return response{kind: pBytes, data: b}

	case rWrite:
		if len(r.data) > maxIOSize {
			return errResp(Err(EINVAL))
		}
		n, err := fs.Write(r.path, r.offset, r.data)
		if err != nil {
			return errResp(err)
		}
		if n > len(r.data) {
			return errResp(Err(EIO))
		}
		return response{kind: pCount, count: uint64(n)}

	case rCreate:
		a, err := fs.Create(r.path, r.attr.toAttr())
		if err != nil {
			return errResp(err)
		}
		w, err := wireAttrFrom(a)
		if err != nil {
			return errResp(err)
		}
		return response{kind: pAttr, attr: w}

	case rMkdir:
		a, err := fs.Mkdir(r.path, r.mode)
		if err != nil {
			return errResp(err)
		}
		w, err := wireAttrFrom(a)
		if err != nil {
			return errResp(err)
		}
		return response{kind: pAttr, attr: w}

	case rRemove:
		attr, err := fs.GetAttr(r.path)
		if err != nil {
			if errnoOf(err) != ENOENT {
				return errResp(err)
			}
		} else if attr.Kind == Dir {
			entries, err := fs.ReadDir(r.path)
			if err != nil {
				return errResp(err)
			}
			if err := checkDirEmptyForRmdir(entries); err != nil {
				return errResp(err)
			}
		}
		if err := fs.Remove(r.path); err != nil {
			return errResp(err)
		}
		return response{kind: pOk}

	case rRename:
		if r.flags&^(RenameNoReplace|RenameExchange) != 0 {
			return errResp(Err(EINVAL))
		}
		if r.flags&RenameNoReplace != 0 && r.flags&RenameExchange != 0 {
			return errResp(Err(EINVAL))
		}
		if r.flags&RenameExchange != 0 {
			return errResp(Err(ENOSYS))
		}
		if rf, ok := fs.(RenameFlagsAware); ok {
			if err := rf.RenameWithFlags(r.from, r.to, r.flags); err != nil {
				return errResp(err)
			}
			return response{kind: pOk}
		}
		if r.flags&RenameNoReplace != 0 {
			if _, err := fs.GetAttr(r.to); err == nil {
				return errResp(Err(EEXIST))
			} else if errnoOf(err) != ENOENT {
				return errResp(err)
			}
		}
		if err := fs.Rename(r.from, r.to); err != nil {
			return errResp(err)
		}
		return response{kind: pOk}

	case rSetAttr:
		a, err := fs.SetAttr(r.path, r.attr.toAttr(), truncateSetAttrValid(SetAttrValid(r.valid)))
		if err != nil {
			return errResp(err)
		}
		w, err := wireAttrFrom(a)
		if err != nil {
			return errResp(err)
		}
		return response{kind: pAttr, attr: w}

	case rSymlink:
		if len(r.target) > maxSymlinkTarget {
			return errResp(Err(ENAMETOOLONG))
		}
		a, err := fs.Symlink(r.path, r.target)
		if err != nil {
			return errResp(err)
		}
		w, err := wireAttrFrom(a)
		if err != nil {
			return errResp(err)
		}
		return response{kind: pAttr, attr: w}

	case rSetXattr:
		if len(r.value) > maxXattrValue {
			return errResp(Err(EINVAL))
		}
		if err := fs.SetXattr(r.path, r.name, r.value, r.flags); err != nil {
			return errResp(err)
		}
		return response{kind: pOk}

	case rGetXattr:
		b, err := fs.GetXattr(r.path, r.name)
		if err != nil {
			return errResp(err)
		}
		return response{kind: pBytes, data: b}

	case rListXattr:
		names, err := fs.ListXattr(r.path)
		if err != nil {
			return errResp(err)
		}
		for _, name := range names {
			if err := validateXattrName(name); err != nil {
				return errResp(err)
			}
		}
		return response{kind: pNames, names: names}

	case rRemoveXattr:
		if err := fs.RemoveXattr(r.path, r.name); err != nil {
			return errResp(err)
		}
		return response{kind: pOk}

	case rFlush:
		if err := fs.Flush(r.path); err != nil {
			return errResp(err)
		}
		return response{kind: pOk}

	case rFsync:
		if err := fs.Fsync(r.path, r.flags&1 != 0); err != nil {
			return errResp(err)
		}
		return response{kind: pOk}

	case rFsyncDir:
		return response{kind: pOk}

	case rStatFs:
		s, err := fs.StatFs()
		if err != nil {
			return errResp(err)
		}
		return response{kind: pStatFs, statfs: statFsToWire(s)}

	default:
		return response{kind: pErr, errno: EIO}
	}
}

func errResp(err error) response {
	return response{kind: pErr, errno: int32(errnoOf(err))}
}

func statFsToWire(s StatFs) statFsWire {
	return statFsWire{
		bsize: s.Bsize, frsize: s.Frsize, blocks: s.Blocks, bfree: s.Bfree,
		bavail: s.Bavail, files: s.Files, ffree: s.Ffree, namemax: s.Namemax,
	}
}
