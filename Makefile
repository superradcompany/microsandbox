# =============================================================================
# Microsandbox Makefile - Build and install microsandbox components
# =============================================================================

# -----------------------------------------------------------------------------
# System Detection and Architecture
# -----------------------------------------------------------------------------
OS := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
	ARCH := arm64
endif
ifeq ($(ARCH),x86_64)
	ARCH := x86_64
endif

# -----------------------------------------------------------------------------
# Build Configuration
# -----------------------------------------------------------------------------
DEBUG ?= 0
LTO ?= 0
CARGO_BUILD_MODE := $(if $(filter 1,$(DEBUG)),,--release)
CARGO_TARGET_DIR := target/$(if $(filter 1,$(DEBUG)),debug,release)

# Set CARGO_PROFILE_RELEASE_LTO based on LTO setting
export CARGO_PROFILE_RELEASE_LTO := $(if $(filter 1,$(LTO)),true,off)

# -----------------------------------------------------------------------------
# Installation Paths
# -----------------------------------------------------------------------------
HOME_LIB := $(HOME)/.local/lib
HOME_BIN := $(HOME)/.local/bin
HOME_SHARE := $(HOME)/.local/share/microsandbox

# -----------------------------------------------------------------------------
# Build Paths and Directories
# -----------------------------------------------------------------------------
MSB_BIN := $(CARGO_TARGET_DIR)/msb
MSBRUN_BIN := $(CARGO_TARGET_DIR)/msbrun
MSBSERVER_BIN := $(CARGO_TARGET_DIR)/msbserver
EXAMPLES_DIR := target/release/examples
BENCHES_DIR := target/release
BUILD_DIR := build
SCRIPT_DIR := scripts
ALIASES_DIR := $(SCRIPT_DIR)/aliases

# -----------------------------------------------------------------------------
# Library Detection
# -----------------------------------------------------------------------------
ifeq ($(OS),Darwin)
	LIBKRUNFW_FILE := $(shell ls $(BUILD_DIR)/libkrunfw.*.dylib 2>/dev/null | head -n1)
	LIBKRUN_FILE := $(shell ls $(BUILD_DIR)/libkrun.*.dylib 2>/dev/null | head -n1)
else
	LIBKRUNFW_FILE := $(shell ls $(BUILD_DIR)/libkrunfw.so.* 2>/dev/null | head -n1)
	LIBKRUN_FILE := $(shell ls $(BUILD_DIR)/libkrun.so.* 2>/dev/null | head -n1)
endif

# -----------------------------------------------------------------------------
# Phony Targets Declaration
# -----------------------------------------------------------------------------
.PHONY: all build install clean build_libkrun example bench bin _run_example _run_bench _run_bin help uninstall microsandbox _build_aliases

# -----------------------------------------------------------------------------
# Main Targets
# -----------------------------------------------------------------------------
all: build

build: build_libkrun
	@$(MAKE) _build_msb
	@$(MAKE) _build_aliases

_build_msb: $(MSB_BIN) $(MSBRUN_BIN) $(MSBSERVER_BIN)
	@mkdir -p $(BUILD_DIR)
	@cp $(MSB_BIN) $(BUILD_DIR)/
	@cp $(MSBRUN_BIN) $(BUILD_DIR)/
	@cp $(MSBSERVER_BIN) $(BUILD_DIR)/
	@echo "Msb build artifacts ($(if $(filter 1,$(DEBUG)),debug,release) mode) copied to $(BUILD_DIR)/"

_build_aliases:
	@mkdir -p $(BUILD_DIR)
	@cp $(ALIASES_DIR)/msr $(BUILD_DIR)/
	@cp $(ALIASES_DIR)/msx $(BUILD_DIR)/
	@cp $(ALIASES_DIR)/msi $(BUILD_DIR)/
	@echo "Alias scripts copied to $(BUILD_DIR)/"

# -----------------------------------------------------------------------------
# Binary Building
# -----------------------------------------------------------------------------
$(MSB_BIN): build_libkrun
	cd microsandbox-core
ifeq ($(OS),Darwin)
	cargo build $(CARGO_BUILD_MODE) --bin msb --features cli $(FEATURES)
else
	cargo build $(CARGO_BUILD_MODE) --bin msb --features cli $(FEATURES)
endif

$(MSBRUN_BIN): build_libkrun
	cd microsandbox-core
ifeq ($(OS),Darwin)
	cargo build $(CARGO_BUILD_MODE) --bin msbrun --features cli $(FEATURES)
	codesign --entitlements microsandbox.entitlements --force -s - $@
else
	cargo build $(CARGO_BUILD_MODE) --bin msbrun --features cli $(FEATURES)
endif

$(MSBSERVER_BIN): build_libkrun
	cd microsandbox-core
ifeq ($(OS),Darwin)
	cargo build $(CARGO_BUILD_MODE) --bin msbserver --features cli $(FEATURES)
else
	cargo build $(CARGO_BUILD_MODE) --bin msbserver --features cli $(FEATURES)
endif

# -----------------------------------------------------------------------------
# Installation
# -----------------------------------------------------------------------------
install: build
	@echo "Installing $(if $(filter 1,$(DEBUG)),debug,release) build..."
	install -d $(HOME_BIN)
	install -d $(HOME_LIB)
	install -d $(HOME_SHARE)
	install -m 755 $(BUILD_DIR)/msb $(HOME_BIN)/msb
	install -m 755 $(BUILD_DIR)/msbrun $(HOME_BIN)/msbrun
	install -m 755 $(BUILD_DIR)/msbserver $(HOME_BIN)/msbserver
	install -m 755 $(BUILD_DIR)/msr $(HOME_BIN)/msr
	install -m 755 $(BUILD_DIR)/msx $(HOME_BIN)/msx
	install -m 755 $(BUILD_DIR)/msi $(HOME_BIN)/msi
	@if [ -n "$(LIBKRUNFW_FILE)" ]; then \
		install -m 755 $(LIBKRUNFW_FILE) $(HOME_LIB)/; \
		cd $(HOME_LIB) && ln -sf $(notdir $(LIBKRUNFW_FILE)) libkrunfw.dylib; \
	else \
		echo "Warning: libkrunfw library not found in build directory"; \
	fi
	@if [ -n "$(LIBKRUN_FILE)" ]; then \
		install -m 755 $(LIBKRUN_FILE) $(HOME_LIB)/; \
		cd $(HOME_LIB) && ln -sf $(notdir $(LIBKRUN_FILE)) libkrun.dylib; \
	else \
		echo "Warning: libkrun library not found in build directory"; \
	fi
	@if [ -f "$(BUILD_DIR)/fex-emu/fex-emu-rootfs.tar.gz" ]; then \
		rm -rf $(HOME_SHARE)/fex-emu; \
		tar -xzf $(BUILD_DIR)/fex-emu/fex-emu-rootfs.tar.gz -C $(HOME_SHARE)/; \
		mv $(HOME_SHARE)/fex-emu-rootfs $(HOME_SHARE)/fex-emu; \
	fi
	@echo "Installation of $(if $(filter 1,$(DEBUG)),debug,release) build complete."

# -----------------------------------------------------------------------------
# Maintenance
# -----------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	cd microsandbox-core && cargo clean && rm -rf build

uninstall:
	rm -f $(HOME_BIN)/msb
	rm -f $(HOME_BIN)/msbrun
	rm -f $(HOME_BIN)/msbserver
	rm -f $(HOME_BIN)/msr
	rm -f $(HOME_BIN)/msx
	rm -f $(HOME_BIN)/msi
	rm -f $(HOME_LIB)/libkrunfw.dylib
	rm -f $(HOME_LIB)/libkrun.dylib
	rm -rf $(HOME_SHARE)/fex-emu
	@if [ -n "$(LIBKRUNFW_FILE)" ]; then \
		rm -f $(HOME_LIB)/$(notdir $(LIBKRUNFW_FILE)); \
	fi
	@if [ -n "$(LIBKRUN_FILE)" ]; then \
		rm -f $(HOME_LIB)/$(notdir $(LIBKRUN_FILE)); \
	fi

build_libkrun:
	./scripts/build_libkrun.sh --no-clean --build-dir "$(BUILD_DIR)"

# Catch-all target to allow example names and arguments
%:
	@:

# -----------------------------------------------------------------------------
# Help Documentation
# -----------------------------------------------------------------------------
help:
	@echo "Microsandbox Makefile Help"
	@echo "======================"
	@echo
	@echo "Main Targets:"
	@echo "  make build                    - Build microsandbox components (release mode, no LTO)"
	@echo "  make install                  - Install binaries and libraries to ~/.local/{bin,lib}"
	@echo "  make uninstall                - Remove all installed components"
	@echo "  make clean                    - Remove build artifacts"
	@echo "  make build_libkrun            - Build libkrun dependency"
	@echo
	@echo "Build Modes:"
	@echo "  make build                    - Build in release mode (fast, no LTO)"
	@echo "  make DEBUG=1 build            - Build in debug mode"
	@echo "  make DEBUG=1 install          - Install debug build"
	@echo
	@echo "LTO Control (Link Time Optimization):"
	@echo "  make LTO=1 build              - Enable LTO for smaller binary (slower build)"
	@echo "  make LTO=1 install            - Install with LTO optimization"
	@echo "  make LTO=0 build              - Disable LTO (default, faster build)"
	@echo
	@echo "Examples:"
	@echo "  # Standard release build (fast, no LTO)"
	@echo "  make build"
	@echo
	@echo "  # Optimized build with LTO (slower build, smaller binary)"
	@echo "  make LTO=1 build"
	@echo
	@echo "  # Debug build for development"
	@echo "  make DEBUG=1 build"
	@echo
	@echo "  # Install standard release build"
	@echo "  make install"
	@echo
	@echo "  # Install optimized build with LTO"
	@echo "  make LTO=1 install"
	@echo
	@echo "Note: LTO (Link Time Optimization) is now disabled by default for faster builds."
	@echo "      Enable it with LTO=1 for smaller, more optimized binaries."
