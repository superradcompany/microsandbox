package vfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// This file mirrors the Rust `vfs::rpc::protocol` wire types. Rust enums use
// serde's external tagging, which CBOR-encodes as:
//   - a unit variant  -> the text string of its name ("StatFs", "Ok")
//   - any other variant -> a 1-entry map { "<Name>": <payload> }
// Structs encode as maps keyed by field name, in declaration order; an
// Option is either CBOR null or the bare value; a tuple is a CBOR array.

var errUnknownField = errors.New("vfs: unknown field in CBOR map")

// nodeKindByte narrows a decoded integer to a known NodeKind byte. The Rust
// scaffold rejects values above Socket; the Go decoder must match, or the two
// sides would disagree on which attr/dir-entry messages are valid.
func nodeKindByte(v uint64) (uint8, error) {
	if v > uint64(Socket) {
		return 0, fmt.Errorf("vfs: unknown node kind %d", v)
	}
	return uint8(v), nil
}

// validateNodeKind rejects outbound provider kinds the wire cannot represent.
func validateNodeKind(k NodeKind) error {
	if k > Socket {
		return Err(EINVAL)
	}
	return nil
}

// knownSetAttrValid is the subset of FUSE setattr bits the runtime scaffold
// understands. Unknown bits are truncated before dispatch, matching Rust's
// SetattrValid::from_bits_truncate.
const knownSetAttrValid = SetMode | SetUID | SetGID | SetSize | SetAtime | SetMtime |
	SetAtimeNow | SetMtimeNow | SetCtime

func truncateSetAttrValid(v SetAttrValid) SetAttrValid {
	return v & knownSetAttrValid
}

// wireAttrFrom encodes provider attributes for the wire, rejecting invalid kinds.
func wireAttrFrom(a Attr) (attrWire, error) {
	if err := validateNodeKind(a.Kind); err != nil {
		return attrWire{}, err
	}
	return attrToWire(a), nil
}

//--------------------------------------------------------------------------------------------------
// Attribute / dir-entry / statfs wire forms
//--------------------------------------------------------------------------------------------------

type optTime struct {
	set  bool
	sec  int64
	nsec uint32
}

func optTimeOf(t time.Time) optTime {
	if t.IsZero() {
		return optTime{}
	}
	sec, nsec := timeToWire(t)
	return optTime{set: true, sec: sec, nsec: nsec}
}

// timeToWire encodes a wall-clock instant using the same pre-epoch floor
// convention as crates/filesystem vfs::rpc::protocol::time_to_wire.
func timeToWire(t time.Time) (sec int64, nsec uint32) {
	sec = t.Unix()
	nsec = uint32(t.Nanosecond())
	if sec >= 0 {
		return sec, nsec
	}
	// Go's Unix() for pre-epoch instants already matches the Rust floor encoding.
	return sec, nsec
}

func (o optTime) toTime() time.Time {
	if !o.set {
		return time.Time{}
	}
	if o.sec >= 0 {
		return time.Unix(o.sec, int64(o.nsec))
	}
	// Match Rust wire_to_time: (-sec) whole seconds before the epoch, then nsec forward.
	return time.Unix(0, 0).Add(-time.Duration(-o.sec)*time.Second + time.Duration(o.nsec))
}

type attrWire struct {
	kind     uint8
	mode     uint32
	size     uint64
	uid      uint32
	gid      uint32
	nlinkSet bool
	nlink    uint64
	rdev     uint32
	atime    optTime
	mtime    optTime
	ctime    optTime
}

func attrToWire(a Attr) attrWire {
	return attrWire{
		kind:     uint8(a.Kind),
		mode:     a.Mode,
		size:     a.Size,
		uid:      a.UID,
		gid:      a.GID,
		nlinkSet: a.Nlink != 0,
		nlink:    a.Nlink,
		rdev:     a.Rdev,
		atime:    optTimeOf(a.Atime),
		mtime:    optTimeOf(a.Mtime),
		ctime:    optTimeOf(a.Ctime),
	}
}

func (w attrWire) toAttr() Attr {
	a := Attr{
		Kind:  NodeKind(w.kind),
		Mode:  w.mode,
		Size:  w.size,
		UID:   w.uid,
		GID:   w.gid,
		Rdev:  w.rdev,
		Atime: w.atime.toTime(),
		Mtime: w.mtime.toTime(),
		Ctime: w.ctime.toTime(),
	}
	if w.nlinkSet {
		a.Nlink = w.nlink
	}
	return a
}

type dirEntryWire struct {
	name []byte
	kind uint8
}

type statFsWire struct {
	bsize, frsize, blocks, bfree, bavail, files, ffree, namemax uint64
}

func (e *encoder) optTime(o optTime) {
	if !o.set {
		e.null()
		return
	}
	e.arrayHead(2)
	e.i64(o.sec)
	e.u64(uint64(o.nsec))
}

func (e *encoder) attr(a attrWire) {
	e.mapHead(10)
	e.text("kind")
	e.u64(uint64(a.kind))
	e.text("mode")
	e.u64(uint64(a.mode))
	e.text("size")
	e.u64(a.size)
	e.text("uid")
	e.u64(uint64(a.uid))
	e.text("gid")
	e.u64(uint64(a.gid))
	e.text("nlink")
	if a.nlinkSet {
		e.u64(a.nlink)
	} else {
		e.null()
	}
	e.text("rdev")
	e.u64(uint64(a.rdev))
	e.text("atime")
	e.optTime(a.atime)
	e.text("mtime")
	e.optTime(a.mtime)
	e.text("ctime")
	e.optTime(a.ctime)
}

func (d *decoder) optTime() (optTime, error) {
	if d.tryNull() {
		return optTime{}, nil
	}
	n, err := d.arrayHead()
	if err != nil {
		return optTime{}, err
	}
	if n != 2 {
		return optTime{}, errors.New("vfs: time tuple must have 2 elements")
	}
	sec, err := d.i64()
	if err != nil {
		return optTime{}, err
	}
	nsec, err := d.u64()
	if err != nil {
		return optTime{}, err
	}
	return optTime{set: true, sec: sec, nsec: uint32(nsec)}, nil
}

func (d *decoder) attr() (attrWire, error) {
	var a attrWire
	n, err := d.mapHead()
	if err != nil {
		return a, err
	}
	for range n {
		key, err := d.text()
		if err != nil {
			return a, err
		}
		switch key {
		case "kind":
			v, e := d.u64()
			if e == nil {
				a.kind, err = nodeKindByte(v)
			} else {
				err = e
			}
		case "mode":
			v, e := d.u64()
			a.mode, err = uint32(v), e
		case "size":
			a.size, err = d.u64()
		case "uid":
			v, e := d.u64()
			a.uid, err = uint32(v), e
		case "gid":
			v, e := d.u64()
			a.gid, err = uint32(v), e
		case "nlink":
			if d.tryNull() {
				a.nlinkSet = false
			} else {
				a.nlink, err = d.u64()
				a.nlinkSet = err == nil
			}
		case "rdev":
			v, e := d.u64()
			a.rdev, err = uint32(v), e
		case "atime":
			a.atime, err = d.optTime()
		case "mtime":
			a.mtime, err = d.optTime()
		case "ctime":
			a.ctime, err = d.optTime()
		default:
			return a, errUnknownField
		}
		if err != nil {
			return a, err
		}
	}
	return a, nil
}

func (e *encoder) dirEntry(de dirEntryWire) {
	e.mapHead(2)
	e.text("name")
	e.bytes(de.name)
	e.text("kind")
	e.u64(uint64(de.kind))
}

func (e *encoder) statFs(s statFsWire) {
	e.mapHead(8)
	e.text("bsize")
	e.u64(s.bsize)
	e.text("frsize")
	e.u64(s.frsize)
	e.text("blocks")
	e.u64(s.blocks)
	e.text("bfree")
	e.u64(s.bfree)
	e.text("bavail")
	e.u64(s.bavail)
	e.text("files")
	e.u64(s.files)
	e.text("ffree")
	e.u64(s.ffree)
	e.text("namemax")
	e.u64(s.namemax)
}

//--------------------------------------------------------------------------------------------------
// Requests
//--------------------------------------------------------------------------------------------------

type reqKind uint8

const (
	rGetAttr reqKind = iota
	rReadDir
	rReadLink
	rRead
	rWrite
	rCreate
	rMkdir
	rRemove
	rRename
	rSetAttr
	rSymlink
	rSetXattr
	rGetXattr
	rListXattr
	rRemoveXattr
	rFlush
	rFsync
	rFsyncDir
	rStatFs
	rGetAttrMany
)

type request struct {
	kind   reqKind
	path   []byte
	name   []byte
	from   []byte
	to     []byte
	target []byte
	value  []byte
	data   []byte
	paths  [][]byte
	offset uint64
	size   uint32
	mode   uint32
	flags  uint32
	valid  uint32
	attr   attrWire
}

func encodeRequest(r request) []byte {
	e := &encoder{}
	field := func(name string) { e.text(name) }
	switch r.kind {
	case rGetAttr:
		e.mapHead(1)
		e.text("GetAttr")
		e.mapHead(1)
		field("path")
		e.bytes(r.path)
	case rGetAttrMany:
		e.mapHead(1)
		e.text("GetAttrMany")
		e.mapHead(1)
		field("paths")
		e.arrayHead(len(r.paths))
		for _, p := range r.paths {
			e.bytes(p)
		}
	case rReadDir:
		e.mapHead(1)
		e.text("ReadDir")
		e.mapHead(3)
		field("path")
		e.bytes(r.path)
		field("offset")
		e.u64(r.offset)
		field("limit")
		limit := uint64(r.size)
		if limit == 0 {
			limit = maxReaddirEntries
		}
		e.u64(limit)
	case rReadLink:
		e.mapHead(1)
		e.text("ReadLink")
		e.mapHead(1)
		field("path")
		e.bytes(r.path)
	case rRead:
		e.mapHead(1)
		e.text("Read")
		e.mapHead(3)
		field("path")
		e.bytes(r.path)
		field("offset")
		e.u64(r.offset)
		field("size")
		e.u64(uint64(r.size))
	case rWrite:
		e.mapHead(1)
		e.text("Write")
		e.mapHead(3)
		field("path")
		e.bytes(r.path)
		field("offset")
		e.u64(r.offset)
		field("data")
		e.bytes(r.data)
	case rCreate:
		e.mapHead(1)
		e.text("Create")
		e.mapHead(2)
		field("path")
		e.bytes(r.path)
		field("attr")
		e.attr(r.attr)
	case rMkdir:
		e.mapHead(1)
		e.text("Mkdir")
		e.mapHead(2)
		field("path")
		e.bytes(r.path)
		field("mode")
		e.u64(uint64(r.mode))
	case rRemove:
		e.mapHead(1)
		e.text("Remove")
		e.mapHead(1)
		field("path")
		e.bytes(r.path)
	case rRename:
		e.mapHead(1)
		e.text("Rename")
		e.mapHead(3)
		field("from")
		e.bytes(r.from)
		field("to")
		e.bytes(r.to)
		field("flags")
		e.u64(uint64(r.flags))
	case rSetAttr:
		e.mapHead(1)
		e.text("SetAttr")
		e.mapHead(3)
		field("path")
		e.bytes(r.path)
		field("attr")
		e.attr(r.attr)
		field("valid")
		e.u64(uint64(r.valid))
	case rSymlink:
		e.mapHead(1)
		e.text("Symlink")
		e.mapHead(2)
		field("path")
		e.bytes(r.path)
		field("target")
		e.bytes(r.target)
	case rSetXattr:
		e.mapHead(1)
		e.text("SetXattr")
		e.mapHead(4)
		field("path")
		e.bytes(r.path)
		field("name")
		e.bytes(r.name)
		field("value")
		e.bytes(r.value)
		field("flags")
		e.u64(uint64(r.flags))
	case rGetXattr:
		e.mapHead(1)
		e.text("GetXattr")
		e.mapHead(2)
		field("path")
		e.bytes(r.path)
		field("name")
		e.bytes(r.name)
	case rListXattr:
		e.mapHead(1)
		e.text("ListXattr")
		e.mapHead(1)
		field("path")
		e.bytes(r.path)
	case rRemoveXattr:
		e.mapHead(1)
		e.text("RemoveXattr")
		e.mapHead(2)
		field("path")
		e.bytes(r.path)
		field("name")
		e.bytes(r.name)
	case rFlush:
		e.mapHead(1)
		e.text("Flush")
		e.mapHead(1)
		field("path")
		e.bytes(r.path)
	case rFsync:
		e.mapHead(1)
		e.text("Fsync")
		e.mapHead(2)
		field("path")
		e.bytes(r.path)
		field("datasync")
		e.bool(r.flags&1 != 0)
	case rFsyncDir:
		e.mapHead(1)
		e.text("FsyncDir")
		e.mapHead(1)
		field("path")
		e.bytes(r.path)
	case rStatFs:
		e.text("StatFs")
	}
	return e.buf
}

func decodeRequest(buf []byte) (request, error) {
	var r request
	if len(buf) == 0 {
		return r, errTruncated
	}
	if err := prevalidateRequestCBOR(buf); err != nil {
		return r, err
	}
	d := &decoder{buf: buf}

	// Unit variant: a bare text string.
	if buf[0]>>5 == majText {
		name, err := d.text()
		if err != nil {
			return r, err
		}
		if name != "StatFs" {
			return r, errors.New("vfs: unknown unit request variant")
		}
		r.kind = rStatFs
		return r, d.finished()
	}

	// Tagged variant: a 1-entry map { "<Name>": <fields> }.
	n, err := d.mapHead()
	if err != nil {
		return r, err
	}
	if n != 1 {
		return r, errors.New("vfs: tagged variant must be a 1-entry map")
	}
	tag, err := d.text()
	if err != nil {
		return r, err
	}

	assign := func(handlers map[string]func() error) error {
		fields, err := d.mapHead()
		if err != nil {
			return err
		}
		for range fields {
			key, err := d.text()
			if err != nil {
				return err
			}
			h, ok := handlers[key]
			if !ok {
				return errUnknownField
			}
			if err := h(); err != nil {
				return err
			}
		}
		return nil
	}
	rbytes := func(dst *[]byte) func() error {
		return func() error { b, e := d.bytes(); *dst = b; return e }
	}
	ru64 := func(dst *uint64) func() error {
		return func() error { v, e := d.u64(); *dst = v; return e }
	}
	ru32 := func(dst *uint32) func() error {
		return func() error { v, e := d.u64(); *dst = uint32(v); return e }
	}
	rattr := func() error { a, e := d.attr(); r.attr = a; return e }

	rbyteslice := func(dst *[][]byte) func() error {
		return func() error {
			n, e := d.arrayLen()
			if e != nil {
				return e
			}
			if n > maxBatchPaths {
				return Err(EINVAL)
			}
			out := make([][]byte, n)
			var totalBytes int
			for i := 0; i < n; i++ {
				b, e := d.bytes()
				if e != nil {
					return e
				}
				totalBytes += len(b)
				if totalBytes > maxBatchPathBytes {
					return Err(EINVAL)
				}
				out[i] = b
			}
			*dst = out
			return nil
		}
	}

	switch tag {
	case "GetAttr":
		r.kind = rGetAttr
		err = assign(map[string]func() error{"path": rbytes(&r.path)})
	case "GetAttrMany":
		r.kind = rGetAttrMany
		err = assign(map[string]func() error{"paths": rbyteslice(&r.paths)})
	case "ReadDir":
		r.kind = rReadDir
		err = assign(map[string]func() error{
			"path":   rbytes(&r.path),
			"offset": ru64(&r.offset),
			"limit":  ru32(&r.size),
		})
	case "ReadLink":
		r.kind = rReadLink
		err = assign(map[string]func() error{"path": rbytes(&r.path)})
	case "Read":
		r.kind = rRead
		err = assign(map[string]func() error{
			"path": rbytes(&r.path), "offset": ru64(&r.offset), "size": ru32(&r.size),
		})
	case "Write":
		r.kind = rWrite
		err = assign(map[string]func() error{
			"path": rbytes(&r.path), "offset": ru64(&r.offset), "data": rbytes(&r.data),
		})
	case "Create":
		r.kind = rCreate
		err = assign(map[string]func() error{"path": rbytes(&r.path), "attr": rattr})
	case "Mkdir":
		r.kind = rMkdir
		err = assign(map[string]func() error{"path": rbytes(&r.path), "mode": ru32(&r.mode)})
	case "Remove":
		r.kind = rRemove
		err = assign(map[string]func() error{"path": rbytes(&r.path)})
	case "Rename":
		r.kind = rRename
		err = assign(map[string]func() error{
			"from": rbytes(&r.from), "to": rbytes(&r.to), "flags": ru32(&r.flags),
		})
	case "SetAttr":
		r.kind = rSetAttr
		err = assign(map[string]func() error{
			"path": rbytes(&r.path), "attr": rattr, "valid": ru32(&r.valid),
		})
	case "Symlink":
		r.kind = rSymlink
		err = assign(map[string]func() error{"path": rbytes(&r.path), "target": rbytes(&r.target)})
	case "SetXattr":
		r.kind = rSetXattr
		err = assign(map[string]func() error{
			"path": rbytes(&r.path), "name": rbytes(&r.name),
			"value": rbytes(&r.value), "flags": ru32(&r.flags),
		})
	case "GetXattr":
		r.kind = rGetXattr
		err = assign(map[string]func() error{"path": rbytes(&r.path), "name": rbytes(&r.name)})
	case "ListXattr":
		r.kind = rListXattr
		err = assign(map[string]func() error{"path": rbytes(&r.path)})
	case "RemoveXattr":
		r.kind = rRemoveXattr
		err = assign(map[string]func() error{"path": rbytes(&r.path), "name": rbytes(&r.name)})
	case "Flush":
		r.kind = rFlush
		err = assign(map[string]func() error{"path": rbytes(&r.path)})
	case "Fsync":
		r.kind = rFsync
		err = assign(map[string]func() error{
			"path": rbytes(&r.path),
			"datasync": func() error {
				v, e := d.boolVal()
				if e != nil {
					return e
				}
				if v {
					r.flags = 1
				}
				return nil
			},
		})
	case "FsyncDir":
		r.kind = rFsyncDir
		err = assign(map[string]func() error{"path": rbytes(&r.path)})
	default:
		return r, errors.New("vfs: unknown request variant: " + tag)
	}
	if err != nil {
		return r, err
	}
	if err := validateRequestLimits(r); err != nil {
		return r, err
	}
	return r, d.finished()
}

// validateRequestLimits rejects wire requests whose declared sizes exceed protocol
// limits before dispatch. Mirrors validate_request_limits in
// crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
func validateRequestLimits(r request) error {
	switch r.kind {
	case rRead:
		if r.size > maxIOSize {
			return Err(EINVAL)
		}
	case rWrite:
		if len(r.data) > maxIOSize {
			return Err(EINVAL)
		}
	case rReadDir:
		if r.size != 0 && int(r.size) > maxReaddirEntries {
			return Err(EINVAL)
		}
	case rSymlink:
		if len(r.target) > maxSymlinkTarget {
			return Err(ENAMETOOLONG)
		}
	case rSetXattr:
		if len(r.value) > maxXattrValue {
			return Err(EINVAL)
		}
	case rGetAttrMany:
		if len(r.paths) > maxBatchPaths {
			return Err(EINVAL)
		}
		totalBytes := 0
		for _, path := range r.paths {
			totalBytes += len(path)
			if totalBytes > maxBatchPathBytes {
				return Err(EINVAL)
			}
		}
	}
	return nil
}

// prevalidateRequestCBOR rejects oversize batches/payloads before allocating the
// full decoded request. Mirrors prevalidate_request_cbor in
// crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
func prevalidateRequestCBOR(buf []byte) error {
	d := &decoder{buf: buf}
	n, err := d.mapHead()
	if err != nil {
		return nil
	}
	if n != 1 {
		return nil
	}
	tag, err := d.text()
	if err != nil {
		return nil
	}
	switch tag {
	case "GetAttrMany":
		return prevalidateGetAttrMany(d)
	case "Write":
		return prevalidateWrite(d)
	case "SetXattr":
		return prevalidateSetXattr(d)
	default:
		return nil
	}
}

func prevalidateGetAttrMany(d *decoder) error {
	n, err := d.mapHead()
	if err != nil {
		return err
	}
	if n != 1 {
		return Err(EINVAL)
	}
	key, err := d.text()
	if err != nil {
		return err
	}
	if key != "paths" {
		return Err(EINVAL)
	}
	count, err := d.arrayLen()
	if err != nil {
		return err
	}
	if count > maxBatchPaths {
		return Err(EINVAL)
	}
	totalBytes := 0
	for i := 0; i < count; i++ {
		n, err := d.skipBytesLen()
		if err != nil {
			return err
		}
		totalBytes += n
		if totalBytes > maxBatchPathBytes {
			return Err(EINVAL)
		}
	}
	return nil
}

func prevalidateWrite(d *decoder) error {
	n, err := d.mapHead()
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		key, err := d.text()
		if err != nil {
			return err
		}
		switch key {
		case "data":
			n, err := d.skipBytesLen()
			if err != nil {
				return err
			}
			if n > maxIOSize {
				return Err(EINVAL)
			}
		case "path":
			if _, err := d.skipBytesLen(); err != nil {
				return err
			}
		case "offset":
			if _, err := d.u64(); err != nil {
				return err
			}
		default:
			return Err(EINVAL)
		}
	}
	return nil
}

func prevalidateSetXattr(d *decoder) error {
	n, err := d.mapHead()
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		key, err := d.text()
		if err != nil {
			return err
		}
		switch key {
		case "value":
			n, err := d.skipBytesLen()
			if err != nil {
				return err
			}
			if n > maxXattrValue {
				return Err(EINVAL)
			}
		case "path", "name":
			if _, err := d.skipBytesLen(); err != nil {
				return err
			}
		case "flags":
			if _, err := d.u64(); err != nil {
				return err
			}
		default:
			return Err(EINVAL)
		}
	}
	return nil
}

//--------------------------------------------------------------------------------------------------
// Responses
//--------------------------------------------------------------------------------------------------

type respKind uint8

const (
	pAttr respKind = iota
	pDir
	pBytes
	pNames
	pCount
	pStatFs
	pOk
	pErr
	pAttrMany
)

// attrResult is one path's outcome in a pAttrMany response: either attributes
// or the Linux errno its getattr failed with.
type attrResult struct {
	ok    bool
	attr  attrWire
	errno int32
}

type response struct {
	kind     respKind
	attr     attrWire
	dir      []dirEntryWire
	data     []byte
	names    [][]byte
	count    uint64
	statfs   statFsWire
	errno    int32
	attrMany []attrResult
}

func encodeResponse(r response) []byte {
	e := &encoder{}
	appendResponse(e, r)
	return e.buf
}

// appendResponse encodes r into e's buffer. Split from encodeResponse so the
// Serve hot path can encode into a pooled encoder.
func appendResponse(e *encoder, r response) {
	switch r.kind {
	case pAttr:
		e.mapHead(1)
		e.text("Attr")
		e.attr(r.attr)
	case pAttrMany:
		e.mapHead(1)
		e.text("AttrMany")
		e.arrayHead(len(r.attrMany))
		for _, ar := range r.attrMany {
			e.mapHead(1)
			if ar.ok {
				e.text("Ok")
				e.attr(ar.attr)
			} else {
				e.text("Err")
				e.i64(int64(ar.errno))
			}
		}
	case pDir:
		e.mapHead(1)
		e.text("Dir")
		e.arrayHead(len(r.dir))
		for _, de := range r.dir {
			e.dirEntry(de)
		}
	case pBytes:
		e.mapHead(1)
		e.text("Bytes")
		e.bytes(r.data)
	case pNames:
		e.mapHead(1)
		e.text("Names")
		e.arrayHead(len(r.names))
		for _, n := range r.names {
			e.bytes(n)
		}
	case pCount:
		e.mapHead(1)
		e.text("Count")
		e.u64(r.count)
	case pStatFs:
		e.mapHead(1)
		e.text("StatFs")
		e.statFs(r.statfs)
	case pOk:
		e.text("Ok")
	case pErr:
		e.mapHead(1)
		e.text("Err")
		e.i64(int64(r.errno))
	}
}

func decodeResponse(buf []byte) (response, error) {
	var r response
	if len(buf) == 0 {
		return r, errTruncated
	}
	d := &decoder{buf: buf}

	if buf[0]>>5 == majText {
		name, err := d.text()
		if err != nil {
			return r, err
		}
		if name != "Ok" {
			return r, errors.New("vfs: unknown unit response variant")
		}
		r.kind = pOk
		return r, d.finished()
	}

	n, err := d.mapHead()
	if err != nil {
		return r, err
	}
	if n != 1 {
		return r, errors.New("vfs: tagged variant must be a 1-entry map")
	}
	tag, err := d.text()
	if err != nil {
		return r, err
	}

	switch tag {
	case "Attr":
		r.kind = pAttr
		r.attr, err = d.attr()
	case "AttrMany":
		r.kind = pAttrMany
		var count int
		if count, err = d.arrayLen(); err == nil {
			r.attrMany = make([]attrResult, count)
			for i := 0; i < count && err == nil; i++ {
				r.attrMany[i], err = d.attrResult()
			}
		}
	case "Dir":
		r.kind = pDir
		var count int
		if count, err = d.arrayLen(); err == nil {
			r.dir = make([]dirEntryWire, count)
			for i := 0; i < count && err == nil; i++ {
				r.dir[i], err = d.dirEntry()
			}
		}
	case "Bytes":
		r.kind = pBytes
		r.data, err = d.bytes()
	case "Names":
		r.kind = pNames
		var count int
		if count, err = d.arrayLen(); err == nil {
			r.names = make([][]byte, count)
			for i := 0; i < count && err == nil; i++ {
				r.names[i], err = d.bytes()
			}
		}
	case "Count":
		r.kind = pCount
		r.count, err = d.u64()
	case "StatFs":
		r.kind = pStatFs
		r.statfs, err = d.statFs()
	case "Err":
		r.kind = pErr
		var v int64
		v, err = d.i64()
		r.errno = int32(v)
	default:
		return r, errors.New("vfs: unknown response variant: " + tag)
	}
	if err != nil {
		return r, err
	}
	return r, d.finished()
}

// attrResult decodes one externally-tagged VAttrResult: a 1-entry map keyed
// "Ok" (an attr map) or "Err" (an errno int).
func (d *decoder) attrResult() (attrResult, error) {
	var ar attrResult
	n, err := d.mapHead()
	if err != nil {
		return ar, err
	}
	if n != 1 {
		return ar, errors.New("vfs: attr result must be a 1-entry map")
	}
	tag, err := d.text()
	if err != nil {
		return ar, err
	}
	switch tag {
	case "Ok":
		ar.ok = true
		ar.attr, err = d.attr()
	case "Err":
		var v int64
		v, err = d.i64()
		ar.errno = int32(v)
	default:
		return ar, errors.New("vfs: unknown attr result variant: " + tag)
	}
	return ar, err
}

func (d *decoder) dirEntry() (dirEntryWire, error) {
	var de dirEntryWire
	n, err := d.mapHead()
	if err != nil {
		return de, err
	}
	for range n {
		key, err := d.text()
		if err != nil {
			return de, err
		}
		switch key {
		case "name":
			de.name, err = d.bytes()
		case "kind":
			v, e := d.u64()
			if e == nil {
				de.kind, err = nodeKindByte(v)
			} else {
				err = e
			}
		default:
			return de, errUnknownField
		}
		if err != nil {
			return de, err
		}
	}
	return de, nil
}

func (d *decoder) statFs() (statFsWire, error) {
	var s statFsWire
	n, err := d.mapHead()
	if err != nil {
		return s, err
	}
	dst := map[string]*uint64{
		"bsize": &s.bsize, "frsize": &s.frsize, "blocks": &s.blocks, "bfree": &s.bfree,
		"bavail": &s.bavail, "files": &s.files, "ffree": &s.ffree, "namemax": &s.namemax,
	}
	for range n {
		key, err := d.text()
		if err != nil {
			return s, err
		}
		p, ok := dst[key]
		if !ok {
			return s, errUnknownField
		}
		if *p, err = d.u64(); err != nil {
			return s, err
		}
	}
	return s, nil
}

//--------------------------------------------------------------------------------------------------
// Handshake: an 8-byte magic + protocol version, exchanged once at channel open.
//--------------------------------------------------------------------------------------------------

// protocolVersion is the VFS wire-protocol version. The msb runtime binary and
// this SDK ship as independently-versioned artifacts, so a skew would otherwise
// surface as an opaque decode error mid-stream; the hello handshake makes it
// fail loudly and immediately instead. Must match the Rust PROTOCOL_VERSION.
//
// Version 2 added the batched GetAttrMany request / AttrMany response.
// Version 4 added FsyncDir to invalidate paginated ReadDir cache entries.
const protocolVersion uint32 = 4

var helloMagic = [4]byte{'M', 'V', 'F', 'S'}

// writeHello writes the 8-byte hello: the 4-byte magic then protocolVersion as
// a big-endian uint32. The responder (this Serve loop) reads the peer's hello
// first, then writes its own — the requester does the reverse — so the exchange
// never deadlocks.
func writeHello(w io.Writer) error {
	var buf [8]byte
	copy(buf[:4], helloMagic[:])
	binary.BigEndian.PutUint32(buf[4:], protocolVersion)
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	return flushWriter(w)
}

// readHello reads and validates a hello, returning the peer's protocol version.
func readHello(r io.Reader) (uint32, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	if !bytes.Equal(buf[:4], helloMagic[:]) {
		return 0, errors.New("vfs: bad protocol magic")
	}
	v := binary.BigEndian.Uint32(buf[4:])
	if v != protocolVersion && v != protocolVersion-1 {
		return 0, fmt.Errorf("vfs: unsupported protocol version %d (supported %d and %d)", v, protocolVersion, protocolVersion-1)
	}
	return v, nil
}

//--------------------------------------------------------------------------------------------------
// Framing: u32 payload length, u64 request id, then the CBOR payload.
//--------------------------------------------------------------------------------------------------

// maxFrameLen caps a single framed message. Sized for a full GetAttrMany batch plus
// CBOR overhead while preventing a corrupt or hostile length prefix from forcing
// multi-megabyte allocations (keep in sync with MAX_FRAME_LEN in
// crates/filesystem/lib/backends/vfs/rpc/protocol.rs).
const maxFrameLen = 2 * 1024 * 1024

// maxSymlinkTarget is the maximum symlink target length accepted on the wire.
const maxSymlinkTarget = 4096

// maxXattrValue is the maximum extended-attribute value length accepted on the wire.
const maxXattrValue = 64 * 1024

// maxIOSize is the maximum bytes per read/write payload (FUSE BIG_WRITES default).
const maxIOSize = 128 * 1024

// maxBatchPaths is the maximum paths in a single GetAttrMany batch.
const maxBatchPaths = 4096

// maxGetAttrManyRpcChunk is the conservative path count per GetAttrMany RPC so
// encoded AttrMany responses stay within maxFrameLen. Keep in sync with
// GETATTR_MANY_RPC_CHUNK in crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
const maxGetAttrManyRpcChunk = 256

// maxBatchPathBytes is the maximum total path bytes in one GetAttrMany request.
const maxBatchPathBytes = 256 * 1024

// maxReaddirEntries is the maximum directory entries in one ReadDir response.
const maxReaddirEntries = 4096

// maxReaddirTotal is the maximum directory entries materialized for one logical listing.
const maxReaddirTotal = 1 << 20

// maxReaddirCachePaths is the maximum distinct directory paths cached per
// connection for paginated ReadDir. Keep in sync with MAX_READDIR_CACHE_PATHS in
// crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
const maxReaddirCachePaths = 64

// maxReaddirFetchRetries bounds refetch attempts when directory-cache generation
// races during pagination. Keep in sync with MAX_READDIR_FETCH_RETRIES in
// crates/filesystem/lib/backends/vfs/rpc/protocol.rs.
const maxReaddirFetchRetries = 64

// writeFrame writes a u32 payload length, a u64 requestID, then the payload.
// The id is echoed from the request so a future multiplexed transport can match
// replies to in-flight requests. Assumes a byte stream (SOCK_STREAM): the
// split-read in readFrame is incompatible with SOCK_SEQPACKET message bounds.
func writeFrame(w io.Writer, requestID uint64, payload []byte) error {
	if len(payload) > maxFrameLen {
		return errors.New("vfs: frame too large")
	}
	var hdr [12]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(payload)))
	binary.BigEndian.PutUint64(hdr[4:], requestID)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return flushWriter(w)
}

func flushWriter(w io.Writer) error {
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func readFrame(r io.Reader) (uint64, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxFrameLen {
		return 0, nil, errors.New("vfs: frame too large")
	}
	var idBuf [8]byte
	if _, err := io.ReadFull(r, idBuf[:]); err != nil {
		return 0, nil, err
	}
	requestID := binary.BigEndian.Uint64(idBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return requestID, buf, nil
}
