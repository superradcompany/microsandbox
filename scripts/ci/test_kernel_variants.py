"""Checks for the kernel variant CI profile boundary."""

import json
import tempfile
import unittest
from pathlib import Path

import kernel_variants


class KernelVariantsTest(unittest.TestCase):
    def test_combined_request_and_resolved_config(self):
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory)
            (firmware / "Makefile").write_text("KERNEL_VERSION = linux-6.12.111\nFULL_VERSION = 5.6.1\n")
            base = "# CONFIG_UDMABUF is not set\nCONFIG_EXT4_FS=y\n"
            (firmware / "config-libkrunfw_aarch64").write_text(base)

            kernel_variants.prepare(firmware, kernel_variants.PROFILES, 5, "aarch64")

            prepared = (firmware / "config-libkrunfw_aarch64").read_text()
            self.assertIn("CONFIG_UDMABUF=y", prepared)
            self.assertIn("CONFIG_WIREGUARD=y", prepared)
            self.assertNotIn("# CONFIG_UDMABUF is not set", prepared)

            source = firmware / "linux-6.12.111"
            source.mkdir()
            required = {
                "CONFIG_WIREGUARD",
                "CONFIG_IP_ADVANCED_ROUTER",
                "CONFIG_IP_MULTIPLE_TABLES",
                "CONFIG_IPV6_MULTIPLE_TABLES",
                "CONFIG_MACVLAN",
                "CONFIG_IPVLAN",
                "CONFIG_UDMABUF",
                "CONFIG_EXT4_FS",
                "CONFIG_EROFS_FS",
                "CONFIG_FUSE_FS",
                "CONFIG_OVERLAY_FS",
                "CONFIG_DRM_VIRTIO_GPU",
                "CONFIG_VIRTIO_INPUT",
            }
            (source / ".config").write_text("".join(f"{key}=y\n" for key in sorted(required)))
            (firmware / "kernel.c").write_text("kernel bundle\n")
            (firmware / "libkrunfw.so.5.6.1").write_text("linked library\n")

            manifest = kernel_variants.verify(firmware, kernel_variants.PROFILES, 5, "aarch64")
            self.assertEqual(manifest["groups"], ["networking", "desktop-buffers"])
            self.assertEqual(manifest["guest_arch"], "aarch64")
            self.assertEqual(manifest["host_target"], "linux-aarch64")

            kernel_manifest = firmware / "kernel-manifest.json"
            kernel_manifest.write_text(json.dumps(manifest))
            linked = firmware / "libkrunfw.5.dylib"
            linked.write_text("macOS linked library\n")
            macos_manifest = kernel_variants.record_link(
                kernel_manifest, firmware / "kernel.c", linked, "darwin-aarch64", kernel_variants.PROFILES
            )
            self.assertEqual(macos_manifest["library_asset"], "libkrunfw-darwin-aarch64-m05.dylib")

            (firmware / "kernel.c").write_text("different kernel bundle\n")
            with self.assertRaisesRegex(ValueError, "kernel_c_sha256"):
                kernel_variants.record_link(
                    kernel_manifest, firmware / "kernel.c", linked, "darwin-aarch64", kernel_variants.PROFILES
                )

            (source / ".config").write_text("".join(f"{key}=y\n" for key in sorted(required - {"CONFIG_UDMABUF"})))
            with self.assertRaisesRegex(ValueError, "CONFIG_UDMABUF"):
                kernel_variants.verify(firmware, kernel_variants.PROFILES, 5, "aarch64")

    def test_publication_requires_every_variant_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            manifests = Path(directory)
            for target, arch in kernel_variants.TARGET_ARCH.items():
                for mask in range(32):
                    names, symbols = kernel_variants.requested_symbols(kernel_variants.PROFILES, mask, arch)
                    manifest = {
                        "schema": 1,
                        "guest_arch": arch,
                        "mask": mask,
                        "groups": names,
                        "host_target": target,
                        "requested_y": sorted(symbols),
                        "profile_sha256": kernel_variants.profile_sha256(kernel_variants.PROFILES),
                        "library_asset": kernel_variants.asset_name(target, mask),
                    }
                    path = manifests / f"manifest-{target}-m{mask:02d}.json"
                    path.write_text(json.dumps(manifest))

            self.assertEqual(len(kernel_variants.index(manifests, kernel_variants.PROFILES)["variants"]), 160)

            (manifests / "manifest-windows-aarch64-m31.json").unlink()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                kernel_variants.index(manifests, kernel_variants.PROFILES)

    def test_profile_identity_ignores_line_endings(self):
        with tempfile.TemporaryDirectory() as directory:
            windows_copy = Path(directory) / "profiles.json"
            text = kernel_variants.PROFILES.read_text()
            windows_copy.write_bytes(text.replace("\n", "\r\n").encode())

            self.assertEqual(
                kernel_variants.profile_sha256(kernel_variants.PROFILES),
                kernel_variants.profile_sha256(windows_copy),
            )


if __name__ == "__main__":
    unittest.main()
