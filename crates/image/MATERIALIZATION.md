# OCI rootfs materialization

This document specifies how one verified OCI layer pipeline feeds microsandbox's layered and flat rootfs representations. It is an implementation contract for `microsandbox-image`; user-facing selection is documented under `msb pull --materialize`.

## Goals

- Download and verify a registry layer only when its reusable EROFS representation is absent or the caller explicitly forces a rebuild.
- Reuse an EROFS layer between unrelated image manifests whenever they share the same ordered OCI `diff_id` content.
- Produce only the rootfs representations requested by the caller.
- Preserve OCI layer ordering, whiteouts, opaque directories, metadata, xattrs, hardlinks, and special files while converting representations.
- Publish cache entries atomically and coordinate concurrent processes without exposing partial artifacts.

## Materialization targets

| Target | Per-layer EROFS | fsmeta + VMDK | Flat ext4 |
|---|---:|---:|---:|
| `layered` | yes | yes | no |
| `flat` | yes | no | yes |
| `all` | yes | yes | yes |

`layered` remains the default. The target changes generated cache artifacts, not OCI resolution or verification. Every target resolves the platform manifest and config so the ordered compressed layer descriptors can be paired with the config's signed uncompressed `diff_id`s.

## Cache identity

- A registry blob is addressed by its compressed descriptor digest and is transient after successful EROFS publication.
- A reusable EROFS layer is addressed by the uncompressed OCI `diff_id`. Compression format and image manifest do not affect its identity.
- Layered fsmeta and VMDK are addressed by the resolved manifest digest because they encode an ordered composition of layers.
- A flat derivation includes the manifest digest, ordered layer `diff_id`s, target platform, and ext4 materializer ABI. The published raw ext4 blob is addressed by its verified byte digest.

The immutable EROFS layer is the common boundary between acquisition and rootfs-specific composition. Flat execution does not mount these layers; it consumes them while creating a complete ext4 artifact.

## Pipeline

1. Resolve the platform-specific manifest and config, then reject mismatched descriptor and `diff_id` counts.
2. For each ordered layer, validate the cached EROFS artifact addressed by `diff_id`.
3. On an EROFS miss, download the compressed blob, verify its descriptor digest, decompress and ingest it, verify the uncompressed `diff_id`, write EROFS to a temporary path, and publish it atomically under a per-layer lock.
4. For `layered` or `all`, merge layer metadata with provenance and publish fsmeta plus VMDK. A missing manifest-specific fsmeta is reconstructed from cached EROFS metadata and block maps; it must not cause a shared layer to be downloaded again.
5. For `flat` or `all`, read the ordered cached EROFS layers, apply OCI merge semantics, write and validate one ext4 candidate, publish its content-addressed blob atomically, and finally replace the manifest reference.
6. Remove transient compressed blobs only after all consumers in the active pull have completed.

`all` runs the shared EROFS stage once and fans out to both compositions. `flat` skips layered-only fsmeta and VMDK generation entirely.

## Cache-hit and force semantics

A normal pull is complete only when every artifact required by its target is valid. Extra representations do not affect the result: a cached flat image does not satisfy `layered` unless fsmeta and VMDK also exist, and layered artifacts do not satisfy `flat` unless its verified ext4 reference exists.

Without `force`, a valid EROFS layer is always reusable, including when the current manifest has never been pulled before. With `force`, registry blobs and derived artifacts are rebuilt according to the existing force contract. `PullPolicy::Always` refreshes the manifest but still reuses content-addressed layers unless `force` is also set. `PullPolicy::Never` succeeds only when all artifacts required by the selected target are already present locally.

## Concurrency and failure rules

- Image-reference locks serialize mutable tag resolution and metadata publication.
- Layer locks use stable files and are rechecked after acquisition so concurrent pulls converge on one EROFS artifact.
- Flat derivation locks serialize ext4 production for identical inputs.
- EROFS, fsmeta, VMDK, flat blobs, and flat references are written through temporary paths and atomically renamed only after validation.
- A failed target-specific composition leaves previously published layers usable. It must not publish a reference to an absent, partial, or size-mismatched artifact.

## Security and correctness boundaries

Registry descriptor digests authenticate compressed bytes; config `diff_id`s authenticate the decompressed layer stream. Reusing EROFS is permitted only after that pair has been verified during its original publication. Readers still validate the structural subset they consume and fail closed on unsupported regular-file layouts, corrupt metadata, invalid device records, missing artifacts, or inconsistent sizes. Target selection never relaxes sandbox isolation or changes the guest-visible filesystem contents.

## Storage and garbage collection

Flat mode retains shared EROFS inputs as well as complete per-image ext4 outputs. This intentionally spends cache capacity to preserve cross-image acquisition reuse and fast rematerialization. Garbage collection must treat manifest metadata, fsmeta/VMDK, flat references, and active sandbox disks as roots and remove an EROFS layer only when no reachable image composition references its `diff_id`.
