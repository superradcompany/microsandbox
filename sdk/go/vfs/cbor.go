package vfs

import (
	"errors"
	"fmt"
	"sync"
)

// A tiny CBOR codec covering exactly the subset the VFS wire protocol uses:
// unsigned/negative integers, byte strings, text strings, definite-length
// arrays and maps, and null. Integers are written in shortest form so the
// output is byte-for-byte identical to the Rust `ciborium` encoder, which lets
// tests compare against fixtures generated on the Rust side.

const (
	majUint  byte = 0
	majNeg   byte = 1
	majBytes byte = 2
	majText  byte = 3
	majArray byte = 4
	majMap   byte = 5

	cborNull  byte = 0xf6
	cborFalse byte = 0xf4
	cborTrue  byte = 0xf5
)

var errTruncated = errors.New("vfs: truncated CBOR input")

//--------------------------------------------------------------------------------------------------
// Encoder
//--------------------------------------------------------------------------------------------------

type encoder struct {
	buf []byte
}

// maxPooledEncoderCap bounds the buffer capacity returned to encoderPool so a
// single oversized reply (e.g. a maxIOSize read) doesn't pin a large buffer in
// the pool for the process lifetime.
const maxPooledEncoderCap = 1 << 20

// encoderPool recycles response-encode buffers across the per-request goroutines
// in Serve, so steady-state replies don't allocate a fresh buffer each time.
var encoderPool = sync.Pool{New: func() any { return &encoder{} }}

// getEncoder returns a reset encoder from the pool.
func getEncoder() *encoder {
	e := encoderPool.Get().(*encoder)
	e.buf = e.buf[:0]
	return e
}

// putEncoder returns an encoder to the pool unless its buffer grew too large to
// be worth retaining.
func putEncoder(e *encoder) {
	if cap(e.buf) <= maxPooledEncoderCap {
		encoderPool.Put(e)
	}
}

func (e *encoder) head(major byte, n uint64) {
	mt := major << 5
	switch {
	case n < 24:
		e.buf = append(e.buf, mt|byte(n))
	case n < 1<<8:
		e.buf = append(e.buf, mt|24, byte(n))
	case n < 1<<16:
		e.buf = append(e.buf, mt|25, byte(n>>8), byte(n))
	case n < 1<<32:
		e.buf = append(e.buf, mt|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		e.buf = append(e.buf, mt|27,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func (e *encoder) u64(n uint64) { e.head(majUint, n) }

func (e *encoder) i64(n int64) {
	if n >= 0 {
		e.head(majUint, uint64(n))
	} else {
		e.head(majNeg, uint64(-1-n))
	}
}

func (e *encoder) bytes(b []byte) {
	e.head(majBytes, uint64(len(b)))
	e.buf = append(e.buf, b...)
}

func (e *encoder) text(s string) {
	e.head(majText, uint64(len(s)))
	e.buf = append(e.buf, s...)
}

func (e *encoder) arrayHead(n int) { e.head(majArray, uint64(n)) }
func (e *encoder) mapHead(n int)   { e.head(majMap, uint64(n)) }
func (e *encoder) null()           { e.buf = append(e.buf, cborNull) }
func (e *encoder) bool(v bool) {
	if v {
		e.buf = append(e.buf, cborTrue)
	} else {
		e.buf = append(e.buf, cborFalse)
	}
}

//--------------------------------------------------------------------------------------------------
// Decoder
//--------------------------------------------------------------------------------------------------

type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) takeByte() (byte, error) {
	if d.pos >= len(d.buf) {
		return 0, errTruncated
	}
	b := d.buf[d.pos]
	d.pos++
	return b, nil
}

func (d *decoder) take(n int) ([]byte, error) {
	// Compare against remaining bytes without forming `d.pos+n`, which would
	// overflow for a length argument near the int max and defeat the check.
	if n < 0 || n > len(d.buf)-d.pos {
		return nil, errTruncated
	}
	b := d.buf[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

// head reads a major type and its argument.
func (d *decoder) head() (major byte, arg uint64, err error) {
	b, err := d.takeByte()
	if err != nil {
		return 0, 0, err
	}
	major = b >> 5
	switch ai := b & 0x1f; {
	case ai < 24:
		arg = uint64(ai)
	case ai == 24:
		x, e := d.take(1)
		if e != nil {
			return 0, 0, e
		}
		arg = uint64(x[0])
	case ai == 25:
		x, e := d.take(2)
		if e != nil {
			return 0, 0, e
		}
		arg = uint64(x[0])<<8 | uint64(x[1])
	case ai == 26:
		x, e := d.take(4)
		if e != nil {
			return 0, 0, e
		}
		arg = uint64(x[0])<<24 | uint64(x[1])<<16 | uint64(x[2])<<8 | uint64(x[3])
	case ai == 27:
		x, e := d.take(8)
		if e != nil {
			return 0, 0, e
		}
		for _, c := range x {
			arg = arg<<8 | uint64(c)
		}
	default:
		return 0, 0, errors.New("vfs: unsupported CBOR additional info (indefinite length?)")
	}
	return major, arg, nil
}

func (d *decoder) expect(major byte) (uint64, error) {
	m, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	if m != major {
		return 0, errors.New("vfs: unexpected CBOR major type")
	}
	return arg, nil
}

func (d *decoder) u64() (uint64, error)    { return d.expect(majUint) }
func (d *decoder) arrayHead() (int, error) { n, e := d.expect(majArray); return int(n), e }
func (d *decoder) mapHead() (int, error)   { n, e := d.expect(majMap); return int(n), e }

// mapLen reads a map header and rejects a count larger than the bytes remaining.
func (d *decoder) mapLen() (int, error) {
	n, err := d.mapHead()
	if err != nil {
		return 0, err
	}
	if n < 0 || n > len(d.buf)-d.pos {
		return 0, errTruncated
	}
	return n, nil
}

// arrayLen reads an array header and rejects a count larger than the bytes
// remaining. Every element occupies at least one byte, so a count that exceeds
// the remaining input is malformed — this prevents a crafted length from
// driving a huge `make`.
func (d *decoder) arrayLen() (int, error) {
	n, err := d.arrayHead()
	if err != nil {
		return 0, err
	}
	if n < 0 || n > len(d.buf)-d.pos {
		return 0, errTruncated
	}
	return n, nil
}

func (d *decoder) i64() (int64, error) {
	m, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	switch m {
	case majUint:
		return int64(arg), nil
	case majNeg:
		return -1 - int64(arg), nil
	default:
		return 0, errors.New("vfs: expected CBOR integer")
	}
}

func (d *decoder) bytes() ([]byte, error) {
	n, err := d.expect(majBytes)
	if err != nil {
		return nil, err
	}
	b, err := d.take(int(n))
	if err != nil {
		return nil, err
	}
	// Copy out: the backing slice is the input buffer.
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// skipBytesLen reads a byte-string header, advances past its payload without
// allocating, and returns the payload length.
func (d *decoder) skipBytesLen() (int, error) {
	n, err := d.expect(majBytes)
	if err != nil {
		return 0, err
	}
	if _, err := d.take(int(n)); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (d *decoder) text() (string, error) {
	n, err := d.expect(majText)
	if err != nil {
		return "", err
	}
	b, err := d.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// tryNull consumes a null if present, reporting whether it did.
func (d *decoder) tryNull() bool {
	if d.pos < len(d.buf) && d.buf[d.pos] == cborNull {
		d.pos++
		return true
	}
	return false
}

func (d *decoder) boolVal() (bool, error) {
	b, err := d.takeByte()
	if err != nil {
		return false, err
	}
	switch b {
	case cborFalse:
		return false, nil
	case cborTrue:
		return true, nil
	default:
		return false, fmt.Errorf("vfs: expected CBOR bool, got 0x%02x", b)
	}
}

// finished reports whether all input has been consumed.
func (d *decoder) finished() error {
	if d.pos != len(d.buf) {
		return errors.New("vfs: trailing bytes after CBOR value")
	}
	return nil
}
