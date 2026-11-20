"""Opt-in live selector reads; reports no credentials or resource metadata."""

import asyncio
import json
import os
import re

from microsandbox import Sandbox, Snapshot, Volume


async def main():
    if os.environ.get("MSB_REMOTE_SELECTOR_LIVE") != "1":
        raise RuntimeError("Set MSB_REMOTE_SELECTOR_LIVE=1 to opt in")
    results = []
    for resource in (Sandbox, Volume, Snapshot):
        try:
            await resource.remote().list()
            result = {"feature": resource.__name__.lower() + "_list", "verdict": "PASS"}
        except Exception as error:  # noqa: BLE001 - report every probe failure without exposing its body
            status = re.search(r"\b(4\d\d|5\d\d)\b", str(error))
            result = {
                "feature": resource.__name__.lower() + "_list",
                "verdict": "FAIL",
                "errorType": type(error).__name__,
                "status": status[1] if status else None,
            }
        results.append(result)
        print(json.dumps(result), flush=True)
    return results


if __name__ == "__main__":
    results = asyncio.run(main())
    if path := os.environ.get("MSB_SELECTOR_REPORT"):
        with open(path, "w") as output:
            json.dump(results, output, indent=2)
            output.write("\n")
    raise SystemExit(int(any(result["verdict"] == "FAIL" for result in results)))
