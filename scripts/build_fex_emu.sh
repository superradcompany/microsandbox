#!/bin/sh
set -e

echo "Installing FEX-Emu dependencies..."
# Install dependencies - ignore transaction warnings at the end
dnf install -y git cmake ninja-build clang lld llvm-devel \
    libstdc++-static libstdc++-devel python3 python3-pip pkgconfig SDL2-devel libepoxy-devel \
    libX11-devel libXrandr-devel libXrender-devel libXi-devel libXxf86vm-devel \
    libXcursor-devel libXinerama-devel wayland-devel wayland-protocols-devel \
    libffi-devel libdrm-devel mesa-libgbm-devel libxkbcommon-devel \
    qt5-qtbase-devel qt5-qtdeclarative-devel nasm 2>&1 | tee /tmp/dnf.log

# Check if dnf actually failed (not just transaction warnings)
if grep -q "Error: " /tmp/dnf.log; then
    echo "ERROR: dnf install failed"
    cat /tmp/dnf.log
    exit 1
fi

# Verify critical build tools were installed
echo "Verifying critical build tools..."
for tool in git cmake ninja clang; do
    if ! command -v $tool >/dev/null 2>&1; then
        echo "ERROR: $tool is not installed"
        cat /tmp/dnf.log
        exit 1
    fi
done
echo "All critical build tools verified successfully"

echo "Installing Python packaging module..."
pip3 install --break-system-packages packaging

echo "Cloning FEX-Emu repository..."
git clone --recurse-submodules https://github.com/FEX-Emu/FEX.git /tmp/FEX

echo "Building FEX-Emu (this may take a while)..."
cd /tmp/FEX
mkdir Build
cd Build
CC=clang CXX=clang++ cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DENABLE_LTO=True \
    -DBUILD_TESTS=False \
    -DENABLE_ASSERTIONS=False \
    -DENABLE_JEMALLOC=False \
    -DENABLE_JEMALLOC_GLIBC_ALLOC=False \
    -DENABLE_OFFLINE_TELEMETRY=False ..
ninja -j4

echo "Installing FEX-Emu to temporary rootfs..."
DESTDIR=/tmp/fex-emu-rootfs ninja install

echo "Creating lib directories..."
mkdir -p /tmp/fex-emu-rootfs/lib64 \
         /tmp/fex-emu-rootfs/lib \
         /tmp/fex-emu-rootfs/usr/lib64

echo "Detecting and copying ARM64 system libraries..."
ldd /tmp/fex-emu-rootfs/usr/bin/FEX | grep -o '/[^ ]*' | sort -u > /tmp/libs.txt
while read lib; do
    if [ -e "$lib" ]; then
        cp -aL "$lib" /tmp/fex-emu-rootfs/lib64/
        cp -aL "$lib" /tmp/fex-emu-rootfs/usr/lib64/
    fi
done < /tmp/libs.txt

echo "Copying dynamic linker..."
find /lib64 /usr/lib64 -name 'ld-linux-aarch64.so*' -exec cp -aL {} /tmp/fex-emu-rootfs/lib64/ \;
cd /tmp/fex-emu-rootfs/lib64
[ -f ld-linux-aarch64.so.1 ] || ln -s ld-*.so.* ld-linux-aarch64.so.1

echo "Copying libFEXCore.so dependencies..."
ldd /tmp/fex-emu-rootfs/usr/lib64/libFEXCore.so | grep -o '/[^ ]*' | sort -u >> /tmp/libs.txt
while read lib; do
    if [ -e "$lib" ]; then
        cp -aL "$lib" /tmp/fex-emu-rootfs/lib64/
        cp -aL "$lib" /tmp/fex-emu-rootfs/usr/lib64/
    fi
done < /tmp/libs.txt

echo "Creating FEX-Emu rootfs tarball..."
cd /tmp
tar czf /output/fex-emu-rootfs.tar.gz fex-emu-rootfs/

echo "FEX-Emu build complete!"
