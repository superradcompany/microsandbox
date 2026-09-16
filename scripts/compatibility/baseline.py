#!/usr/bin/env python3
"""Pin one published release and verify its Linux runtime for every CI lane."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import urllib.request


REPOSITORY = "superradcompany/microsandbox"
BUNDLE = "microsandbox-linux-x86_64.tar.gz"
GO_FFI = "libmicrosandbox_go_ffi-linux-amd64.so"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def request(url):
    headers = {"User-Agent": "microsandbox-compatibility-ci"}
    # Never forward the API token to package registries or asset download hosts.
    if url.startswith("https://api.github.com/") and os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60)


def read_json(url):
    with request(url) as response:
        return json.load(response)


def verify(path, checksums):
    expected = [line.split()[0] for line in checksums.splitlines()
                if len(line.split()) == 2 and line.split()[1].lstrip("*") == path.name]
    if expected != [sha256(path)]:
        raise ValueError(f"missing, duplicated or mismatched checksum: {path.name}")


def unpack_runtime(bundle, destination):
    with tarfile.open(bundle, "r:gz") as archive:
        members = archive.getmembers()
        firmware = [entry.name for entry in members
                    if re.fullmatch(r"libkrunfw\.so\.\d+\.\d+\.\d+", entry.name)]
        if len(firmware) != 1:
            raise ValueError("expected exactly one versioned firmware file")
        for name in ["msb", firmware[0]]:
            matches = [entry for entry in members if entry.name == name]
            if len(matches) != 1 or not matches[0].isfile():
                raise ValueError(f"expected one regular release file: {name}")
            # Do not extract paths, archive symlinks, permissions or ownership.
            with archive.extractfile(matches[0]) as source, (destination / name).open("wb") as target:
                shutil.copyfileobj(source, target)
            (destination / name).chmod(0o700 if name == "msb" else 0o600)
    return firmware[0]


def resolve(output):
    output.mkdir(parents=True, exist_ok=False)
    release = read_json(f"https://api.github.com/repos/{REPOSITORY}/releases/latest")
    tag = release["tag_name"]
    if release["draft"] or release["prerelease"] or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("baseline must be a stable published release")
    # Resolve the tag now; all matrix jobs consume this record, never 'latest'.
    ref = read_json(f"https://api.github.com/repos/{REPOSITORY}/git/ref/tags/{tag}")["object"]
    while ref["type"] == "tag":
        ref = read_json(f"https://api.github.com/repos/{REPOSITORY}/git/tags/{ref['sha']}")["object"]
    if ref["type"] != "commit":
        raise ValueError("release tag must resolve to a commit")
    assets = {entry["name"]: entry for entry in release["assets"]}
    if len(assets) != len(release["assets"]):
        raise ValueError("duplicate release asset names")
    for name in ("checksums.sha256", BUNDLE, GO_FFI):
        url = assets[name]["browser_download_url"]
        if not url.startswith(f"https://github.com/{REPOSITORY}/releases/download/{tag}/"):
            raise ValueError("unexpected release asset URL")
        with request(url) as source, (output / name).open("wb") as target:
            shutil.copyfileobj(source, target)
    checksums = (output / "checksums.sha256").read_text()
    verify(output / BUNDLE, checksums)
    verify(output / GO_FFI, checksums)
    firmware = unpack_runtime(output / BUNDLE, output)
    gems = read_json("https://rubygems.org/api/v1/versions/microsandbox.json")
    modern = [item["number"] for item in gems
              if re.fullmatch(r"\d+\.\d+\.\d+", item["number"])
              and tuple(map(int, item["number"].split("."))) >= (0, 7, 0)]
    # The unrelated Ruby 0.1 SDK is outside the supported compatibility floor.
    # Once a modern gem exists, a missing matching gem is a publication failure,
    # not permission to silently drop reverse-direction coverage.
    if modern and tag[1:] not in modern:
        raise ValueError(f"Ruby SDK {tag} is missing from the release train")
    record = dict(tag=tag, version=tag[1:], commit=ref["sha"], release_url=release["html_url"],
                  ruby_released=bool(modern), firmware=firmware,
                  hashes={name: sha256(output / name) for name in ("msb", firmware, GO_FFI, BUNDLE)})
    (output / "baseline.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    resolve(parser.parse_args().output)
