# sample-images

Pre-built disk images used by the microsandbox examples. Each file is a
small filesystem with a few seeded files so the examples have something
recognisable to read and write.

## Files

| File | Format | Filesystem | Virtual size | Notes |
|---|---|---|---|---|
| `ext4-seeded.raw` | raw | ext4 | 8 MiB | sparse on disk (~700 KiB) |
| `ext4-seeded.qcow2` | qcow2 | ext4 | 8 MiB | naturally compact (~640 KiB) |

Both images carry the same filesystem; the qcow2 is just the raw wrapped
in qcow2 format.

## Seeded layout

```
/
├── empty-dir/                 (empty directory)
├── hello.txt                  short greeting
├── lib/
│   └── data.json              small JSON document
├── lost+found/                ext4 default
├── notes/
│   ├── changelog.txt          two-line release notes
│   └── release.txt            "v1.0.0"
└── readme.txt                 one-line description
```

Filesystem label is `msb-disk-data`.
