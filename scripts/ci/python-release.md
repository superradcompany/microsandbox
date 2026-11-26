# Python release publishing

The release workflow publishes `microsandbox-core` first, waits for its exact wheel hash to appear on PyPI, and then publishes `microsandbox`, `microsandbox-local`, and `microsandbox-remote` in separate jobs. Every publisher consumes the same immutable wheel artifact that passed release validation. The jobs run only after the existing release and production-smoke gates pass; pull requests and build-only dispatches do not publish.

## Required setup before the next release

Configure these environments in `superradcompany/microsandbox` on GitHub. Copy the existing `pypi` environment's reviewers, deployment branch/tag rules, and other protection settings to each new environment before enabling publication. Creating an environment name in YAML alone does not copy its protections.

| PyPI project | GitHub environment | PyPI publisher kind before first upload |
| --- | --- | --- |
| `microsandbox` | `pypi` | Existing project publisher, unchanged |
| `microsandbox-core` | `pypi-core` | Pending publisher |
| `microsandbox-local` | `pypi-local` | Pending publisher |
| `microsandbox-remote` | `pypi-remote` | Pending publisher |

For all four publishers, use GitHub owner `superradcompany`, repository `microsandbox`, and workflow filename `release.yml`. The environment field must match the table exactly. Publishing uses GitHub OIDC with `id-token: write`, not a PyPI API token.

If core already has a pending publisher using environment `pypi`, replace that pending entry with `pypi-core`. Leave the existing `microsandbox` project publisher unchanged. If any of the other projects has already been created, configure its publisher under that project's Publishing settings instead of registering a pending publisher.

PyPI permits only one pending project per identical publisher configuration. The distinct environment claims let all three pending entries coexist before the next release. On first use, PyPI creates each project and converts its pending publisher into an ordinary publisher. No placeholder release or manual package upload is needed. Pending publishers do not reserve project names. See [PyPI's project creation documentation](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

This PR does not change the external GitHub or PyPI settings. Complete and verify that setup before cutting the next tag. It also does not repair the already-uploaded `microsandbox==0.8.1`, which still requires the missing `microsandbox-core==0.8.1` release if that dependency remains unpublished.

## Wheel collection and retries

Download each platform's `python-sdk-*` artifact into its own directory. `python_release.py collect` checks every wheel's ZIP integrity and package identity, requires all four distributions from all five platforms, and rejects unexpected native-wheel filename collisions. Core is platform independent and appears in every platform artifact with the same filename. The collector consistently selects core from `python-sdk-darwin-aarch64`; other copies are checked but never overwrite it. This avoids concurrent extraction corrupting a shared destination and avoids choosing the Windows-generated text variant by accident.

The resulting 16 wheels pass the existing manifest, platform, and installation checks before being saved as `python-release-wheels`. Publishing does not merge the original platform artifacts again. Each job selects only its own project's wheels, checks them again, requires trusted publishing, and uses `uv publish --check-url https://pypi.org/simple/` for retry-safe uploads. After upload, it checks public PyPI filenames and SHA-256 digests with bounded retries. A different hash for an existing filename is an error; published files are never replaced.

If core publication or indexing fails, dependent publishers stay blocked. If one SDK publisher fails, the other SDK publishers can finish, and failed jobs can be retried using the validated artifact from the same run. Registry publication is not atomic across projects; inspect the failed job's authentication, upload, or indexing error before retrying.

## Local checks

```sh
python3 -m unittest scripts.ci.test_python_release scripts.ci.test_validate_release_artifacts
# Requires PyYAML, as installed by the Check workflow's release-note checks.
node --test scripts/ci/test-release-context.cjs
```

The publication tests mock uploads and registry responses. The release workflow additionally checks real built wheels on PRs, but end-to-end production OIDC publication is only verified by an authorized release after the external setup is complete.
