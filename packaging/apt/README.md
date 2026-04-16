# APT Packaging

This directory contains the Debian/Ubuntu packaging metadata used to build the
`microsandbox` APT package and the signed repository published at
`https://apt.microsandbox.dev`.

## Contents

- `control.template`: package control metadata rendered by `scripts/package-deb.sh`
- `release.conf.template`: `apt-ftparchive` release metadata rendered by
  `scripts/build-apt-repo.sh`
- `copyright`: Debian machine-readable copyright file installed into the package

## Local flow

1. Build baseline-compatible Linux artifacts with
   `scripts/build-apt-baseline-artifacts.sh --output-dir build/apt/<arch>`
2. Create `.deb` packages with `scripts/package-deb.sh`
3. Generate a signing key with `scripts/generate-apt-test-key.sh` or import the
   production key with `scripts/import-apt-signing-key.sh`
4. Build the signed repository with `scripts/build-apt-repo.sh`

The CI workflows use the same scripts for PR validation, release publication,
and canary smoke tests.
