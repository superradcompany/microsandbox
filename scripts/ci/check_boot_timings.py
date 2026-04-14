#!/usr/bin/env python3

import argparse
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def run_sample(binary: str) -> dict:
    proc = subprocess.run(
        [binary],
        check=True,
        capture_output=True,
        text=True,
    )
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError("benchmark binary produced no stdout")
    return json.loads(stdout)


def metric_summary(samples: list[dict], key: str) -> dict:
    values = [sample[key] for sample in samples]
    return {
        "samples": values,
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
    }


def render_summary(results: dict, failures: list[str]) -> str:
    labels = {
        "enter_to_boot": "vm enter -> boot",
        "boot_to_init": "boot -> init",
    }
    lines = [
        "## Boot timing gate",
        "",
        "| Metric | Median (ms) | Min | Max | Baseline | Max regression | Max threshold |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for metric in ("enter_to_boot", "boot_to_init"):
        summary = results["metrics"][metric]
        lines.append(
            "| {metric} | {median:.3f} | {minimum:.3f} | {maximum:.3f} | {baseline:.3f} | {regression:.3f} | {threshold:.3f} |".format(
                metric=labels[metric],
                median=summary["median_ms"],
                minimum=summary["min_ms"],
                maximum=summary["max_ms"],
                baseline=summary["baseline_ms"],
                regression=summary["max_regression_ms"],
                threshold=summary["max_threshold_ms"],
            )
        )

    lines.append("")
    if failures:
        lines.append("Result: failed")
        lines.extend(f"- {failure}" for failure in failures)
    else:
        lines.append("Result: passed")

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    config = json.loads(Path(args.config).read_text())

    for _ in range(int(config["warmups"])):
        run_sample(args.binary)

    raw_samples = [run_sample(args.binary) for _ in range(int(config["samples"]))]

    enter_to_boot = metric_summary(raw_samples, "enter_to_boot_ms")
    boot_to_init = metric_summary(raw_samples, "boot_to_init_ms")

    results = {
        "raw_samples": raw_samples,
        "metrics": {
            "enter_to_boot": {
                "median_ms": enter_to_boot["median"],
                "min_ms": enter_to_boot["minimum"],
                "max_ms": enter_to_boot["maximum"],
                "baseline_ms": config["baseline_ms"]["enter_to_boot"],
                "max_regression_ms": config["max_regression_ms"]["enter_to_boot"],
                "max_threshold_ms": config["max_threshold_ms"]["enter_to_boot"],
            },
            "boot_to_init": {
                "median_ms": boot_to_init["median"],
                "min_ms": boot_to_init["minimum"],
                "max_ms": boot_to_init["maximum"],
                "baseline_ms": config["baseline_ms"]["boot_to_init"],
                "max_regression_ms": config["max_regression_ms"]["boot_to_init"],
                "max_threshold_ms": config["max_threshold_ms"]["boot_to_init"],
            },
        },
    }

    failures = []
    for metric, summary in results["metrics"].items():
        if summary["median_ms"] > summary["max_threshold_ms"]:
            failures.append(
                f"{metric} median {summary['median_ms']:.3f}ms exceeded max threshold {summary['max_threshold_ms']:.3f}ms"
            )

        regression = summary["median_ms"] - summary["baseline_ms"]
        if regression > summary["max_regression_ms"]:
            failures.append(
                f"{metric} median regressed by {regression:.3f}ms (baseline {summary['baseline_ms']:.3f}ms, allowed {summary['max_regression_ms']:.3f}ms)"
            )

    Path(args.output).write_text(json.dumps(results, indent=2) + "\n")

    summary = render_summary(results, failures)
    print(summary, end="")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
