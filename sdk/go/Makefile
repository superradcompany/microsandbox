REPO_ROOT := $(shell git -C "$(dir $(abspath $(lastword $(MAKEFILE_LIST))))" rev-parse --show-toplevel)
RUST_TARGET_DIR := $(REPO_ROOT)/target

.PHONY: build test test-integration clean

# Build the Rust FFI staticlib (debug profile).
build:
	cargo build -p microsandbox-go-ffi --manifest-path "$(REPO_ROOT)/Cargo.toml"

# Run pure unit tests (no CGO, no live sandbox required).
test:
	go test ./...

# Build the Rust lib then run all tests including integration tests.
# Requires a running microsandbox daemon.
test-integration: build
	CGO_LDFLAGS="-L$(RUST_TARGET_DIR)/debug" go test -tags integration -v -timeout 10m ./...

# Build the Rust lib with release optimisations, then run integration tests.
test-integration-release:
	cargo build -p microsandbox-go-ffi --release --manifest-path "$(REPO_ROOT)/Cargo.toml"
	CGO_LDFLAGS="-L$(RUST_TARGET_DIR)/release" go test -tags integration -v -timeout 10m ./...

clean:
	go clean ./...
