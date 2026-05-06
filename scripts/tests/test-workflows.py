#!/usr/bin/env python3

from pathlib import Path
import sys

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_WORKFLOW = REPO_ROOT / ".github/workflows/check.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github/workflows/release.yml"


def load_workflow(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def workflow_on(document: dict) -> dict:
    return document.get("on", document.get(True, {}))


def find_checkout_step(document: dict, job_name: str) -> dict | None:
    steps = document["jobs"][job_name]["steps"]
    return next((step for step in steps if step.get("uses") == "actions/checkout@v4"), None)


def main() -> int:
    failures: list[str] = []

    check_text = CHECK_WORKFLOW.read_text(encoding="utf-8")
    release_text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    check = load_workflow(CHECK_WORKFLOW)
    release = load_workflow(RELEASE_WORKFLOW)

    if workflow_on(release).get("push", {}).get("tags") != ["v*"]:
        failures.append("release.yml must publish from push tags ['v*']")

    if "workflow_run" in release_text:
        failures.append("release.yml must not depend on workflow_run context")

    if "prepare" in release.get("jobs", {}):
        failures.append("release.yml must not gate publication behind a prepare job")

    if "release-metadata" in check_text:
        failures.append("check.yml must not carry unreachable release metadata artifacts")

    for document, path, job_name in [
        (check, CHECK_WORKFLOW, "apt-package-test"),
        (release, RELEASE_WORKFLOW, "apt-package"),
    ]:
        checkout = find_checkout_step(document, job_name)
        if checkout is None:
            failures.append(f"{path.name}:{job_name} must define an actions/checkout@v4 step")
            continue
        if checkout.get("with", {}).get("submodules") is not True:
            failures.append(f"{path.name}:{job_name} checkout must enable submodules")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("workflow structure checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
