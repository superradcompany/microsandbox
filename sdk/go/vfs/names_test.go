package vfs

import (
	"bytes"
	"testing"
)

func TestValidateXattrName(t *testing.T) {
	cases := []struct {
		name []byte
		want int
	}{
		{[]byte("user.foo"), 0},
		{[]byte(""), EINVAL},
		{[]byte("user/foo"), EINVAL},
	}
	for _, tc := range cases {
		err := validateXattrName(tc.name)
		if tc.want == 0 {
			if err != nil {
				t.Fatalf("validateXattrName(%q) = %v, want nil", tc.name, err)
			}
			continue
		}
		if errnoOf(err) != tc.want {
			t.Fatalf("validateXattrName(%q) errno = %d, want %d (%v)", tc.name, errnoOf(err), tc.want, err)
		}
	}
}

func TestCheckDirEmptyForRmdir(t *testing.T) {
	if err := checkDirEmptyForRmdir(nil); err != nil {
		t.Fatalf("empty listing: %v", err)
	}
	if err := checkDirEmptyForRmdir([]DirEntry{{Name: []byte("child"), Kind: File}}); errnoOf(err) != ENOTEMPTY {
		t.Fatalf("nonempty: got %v", err)
	}
	long := make([]byte, maxReaddirNameLen+1)
	if err := checkDirEmptyForRmdir([]DirEntry{{Name: long, Kind: File}}); errnoOf(err) != EIO {
		t.Fatalf("invalid-only: got %v", err)
	}
	if err := checkDirEmptyForRmdir([]DirEntry{{Name: []byte("child"), Kind: NodeKind(99)}}); errnoOf(err) != ENOTEMPTY {
		t.Fatalf("invalid kind with valid name counts as visible: got %v", err)
	}
}

func TestDispatchRejectsInvalidXattrName(t *testing.T) {
	fs := stubPathFs{}
	resp := dispatch(fs, request{
		kind: rSetXattr,
		path: []byte("/a"),
		name: []byte("bad/name"),
	}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EINVAL {
		t.Fatalf("bad xattr name = %+v, want Err(EINVAL)", resp)
	}
}

func TestValidateReaddirName(t *testing.T) {
	cases := []struct {
		name []byte
		want int
	}{
		{[]byte("ok.txt"), 0},
		{[]byte("."), EPERM},
		{[]byte(".."), EPERM},
		{[]byte("a/b"), EPERM},
		{[]byte(""), EINVAL},
		{[]byte("a\x00b"), EINVAL},
		{bytes.Repeat([]byte("a"), maxReaddirNameLen+1), ENAMETOOLONG},
	}
	for _, tc := range cases {
		err := validateReaddirName(tc.name)
		if tc.want == 0 {
			if err != nil {
				t.Fatalf("validateReaddirName(%q) = %v, want nil", tc.name, err)
			}
			continue
		}
		if errnoOf(err) != tc.want {
			t.Fatalf("validateReaddirName(%q) errno = %d, want %d (%v)", tc.name, errnoOf(err), tc.want, err)
		}
	}
}

func TestValidateSymlinkTargetRejectsLongTarget(t *testing.T) {
	err := validateSymlinkTarget(bytes.Repeat([]byte("a"), maxSymlinkTarget+1))
	if errnoOf(err) != ENAMETOOLONG {
		t.Fatalf("long symlink target errno = %d, want %d (%v)", errnoOf(err), ENAMETOOLONG, err)
	}
}

func TestDispatchRejectsOversizedIO(t *testing.T) {
	fs := stubPathFs{}
	resp := dispatch(fs, request{kind: rRead, path: []byte("/a"), size: maxIOSize + 1}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EINVAL {
		t.Fatalf("oversized read = %+v, want Err(EINVAL)", resp)
	}
	resp = dispatch(fs, request{kind: rWrite, path: []byte("/a"), data: make([]byte, maxIOSize+1)}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EINVAL {
		t.Fatalf("oversized write = %+v, want Err(EINVAL)", resp)
	}
	resp = dispatch(fs, request{kind: rSymlink, path: []byte("/a"), target: bytes.Repeat([]byte("a"), maxSymlinkTarget+1)}, &readDirCache{})
	if resp.kind != pErr || resp.errno != ENAMETOOLONG {
		t.Fatalf("oversized symlink target = %+v, want Err(ENAMETOOLONG)", resp)
	}
	resp = dispatch(fs, request{
		kind: rSetXattr, path: []byte("/a"), name: []byte("user.foo"),
		value: make([]byte, maxXattrValue+1),
	}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EINVAL {
		t.Fatalf("oversized xattr value = %+v, want Err(EINVAL)", resp)
	}
}

func TestDispatchRejectsInvalidReadLinkTarget(t *testing.T) {
	fs := readLinkFs{target: []byte("../etc/passwd")}
	resp := dispatch(fs, request{kind: rReadLink, path: []byte("/link")}, &readDirCache{})
	if resp.kind != pErr || resp.errno != EPERM {
		t.Fatalf("bad readlink target = %+v, want Err(EPERM)", resp)
	}
}

func TestDispatchSkipsBadReaddirNames(t *testing.T) {
	fs := badReaddirFs{}
	resp := dispatch(fs, request{kind: rReadDir, path: []byte("/")}, &readDirCache{})
	if resp.kind != pDir {
		t.Fatalf("bad readdir = %+v, want pDir (skip bad entries, not fail)", resp)
	}
	// The unrepresentable names are skipped; only the valid sibling survives.
	if len(resp.dir) != 1 || string(resp.dir[0].name) != "good" {
		t.Fatalf("readdir entries = %+v, want exactly [good]", resp.dir)
	}
}

type stubPathFs struct{ ReadOnly }

func (stubPathFs) GetAttr(path []byte) (Attr, error) {
	if string(path) == "/a" {
		return Attr{Kind: File, Mode: 0o644}, nil
	}
	return Attr{}, Err(ENOENT)
}

func (stubPathFs) ReadDir(path []byte) ([]DirEntry, error) { return nil, Err(ENOENT) }

func (stubPathFs) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	return nil, nil
}

type readLinkFs struct {
	stubPathFs
	target []byte
}

func (f readLinkFs) GetAttr(path []byte) (Attr, error) {
	if string(path) == "/link" {
		return Attr{Kind: Symlink, Mode: 0o777}, nil
	}
	return f.stubPathFs.GetAttr(path)
}

func (f readLinkFs) ReadLink(path []byte) ([]byte, error) {
	if string(path) == "/link" {
		return f.target, nil
	}
	return nil, Err(ENOENT)
}

type badReaddirFs struct{ ReadOnly }

func (badReaddirFs) GetAttr(path []byte) (Attr, error) {
	if string(path) == "/" {
		return Attr{Kind: Dir, Mode: 0o755}, nil
	}
	return Attr{}, Err(ENOENT)
}

func (badReaddirFs) ReadDir(path []byte) ([]DirEntry, error) {
	if string(path) == "/" {
		return []DirEntry{
			{Name: []byte(".."), Kind: File},
			{Name: []byte("."), Kind: File},
			{Name: []byte("a/b"), Kind: File},
			{Name: nil, Kind: File},
			{Name: []byte("good"), Kind: File},
		}, nil
	}
	return nil, Err(ENOENT)
}

func (badReaddirFs) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	return nil, nil
}
