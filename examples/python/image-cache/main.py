"""Image cache example - list, inspect, and prune cached OCI images."""

import asyncio
import time
from datetime import datetime, timezone

from microsandbox import Image, Sandbox

TARGET_IMAGE = "mirror.gcr.io/library/alpine"


async def main():
    name = f"py-image-cache-{int(time.time())}"

    print(f"Seeding image cache with {TARGET_IMAGE}")
    sandbox = await Sandbox.create(
        name,
        image=Image.oci(TARGET_IMAGE),
        cpus=1,
        memory=512,
        replace=True,
        pull_policy="if_missing",
    )
    try:
        output = await sandbox.shell("cat /etc/os-release | head -n 1")
        print(output.stdout_text.strip())
    finally:
        await sandbox.stop_and_wait()
        await Sandbox.remove(name)

    images = await Image.list()
    print(f"\nImage.list() -> {len(images)} cached image(s)")
    for image in images:
        print(
            f"  {image.reference} "
            f"os={image.os or '-'} arch={image.architecture or '-'} "
            f"layers={image.layer_count} size={format_bytes(image.size_bytes)}"
        )

    handle = await Image.get(TARGET_IMAGE)
    print(f"\nImage.get({TARGET_IMAGE!r})")
    print(f"  manifest_digest={handle.manifest_digest or '-'}")
    print(f"  created_at={format_timestamp(handle.created_at)}")
    print(f"  last_used_at={format_timestamp(handle.last_used_at)}")

    detail = await handle.inspect()
    print(f"\nhandle.inspect() -> {len(detail.layers)} layer(s)")
    if detail.config is not None:
        print(f"  entrypoint={detail.config.entrypoint}")
        print(f"  cmd={detail.config.cmd}")
        print(f"  working_dir={detail.config.working_dir or '-'}")
        print(f"  user={detail.config.user or '-'}")

    for layer in detail.layers:
        print(
            f"  [{layer.position}] diff={short_digest(layer.diff_id)} "
            f"blob={short_digest(layer.blob_digest)} "
            f"compressed={format_bytes(layer.compressed_size_bytes)}"
        )

    report = await Image.prune()
    print("\nImage.prune()")
    print(f"  image_refs_removed={report.image_refs_removed}")
    print(f"  manifests_removed={report.manifests_removed}")
    print(f"  layers_removed={report.layers_removed}")
    print(f"  fsmeta_removed={report.fsmeta_removed}")
    print(f"  vmdk_removed={report.vmdk_removed}")
    print(f"  bytes_reclaimed={format_bytes(report.bytes_reclaimed)}")

    print("\nUse await Image.remove(reference, force=True) to delete one cached image explicitly.")


def format_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    mib = value / (1024 * 1024)
    return f"{mib:.1f} MiB"


def format_timestamp(value: float | None) -> str:
    if value is None:
        return "-"
    seconds = value / 1000
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def short_digest(value: str) -> str:
    if len(value) <= 20:
        return value
    return f"{value[:20]}..."


if __name__ == "__main__":
    asyncio.run(main())
