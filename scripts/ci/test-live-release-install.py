"""Run the Versions examples with real release bundles in disposable homes.

Only the bootstrap URL changes in PR mode: a loopback server serves this
checkout's installers. GitHub metadata, checksums, bundles and registries are
always real. Deployed mode leaves the documented URLs untouched.
"""

import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request
import urllib.error


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/getting-started/versions.mdx"
API = "https://api.github.com/repos/superradcompany/microsandbox/releases"


def read_bytes(url):
    headers = {"User-Agent": "microsandbox-live-install-smoke"}
    # Authenticate only harness metadata requests on GitHub-hosted runners.
    # Never forward this credential to registries, bootstrap URLs or installers.
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def read_json(url):
    return json.loads(read_bytes(url))


def snippet(section, label):
    body = DOCS.read_text().split("## " + section + "\n", 1)[1].split("\n## ", 1)[0]
    matches = re.findall(r"```\w+ " + re.escape(label) + r"\n(.*?)```", body, re.S)
    if len(matches) != 1:
        raise ValueError(f"Expected one {label} example in {section}")
    return matches[0]


def isolated_environment(root):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MSB_") and key not in ("GH_TOKEN", "GITHUB_TOKEN")}
    # HOME also isolates the Unix installer's ~/.local/bin command links.
    home = root / "home"
    home.mkdir(parents=True)
    env.update(HOME=str(home), USERPROFILE=str(home), MSB_HOME=str(home / ".microsandbox"),
               MSB_INSTALL_NO_PATH="1", MSB_INSTALL_NO_DOCTOR="1", MSB_INSTALL_NO_FIX="1",
               npm_config_cache=str(root / "npm-cache"))
    return env


def command(args, cwd, env, timeout=600):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, encoding="utf-8",
                            errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command exited {result.returncode}: {args}\n{result.stdout[-8000:]}")
    return result.stdout


def assert_version(output, version):
    if not re.search(r"(?<![\w.])" + re.escape(version) + r"(?![\w.+-])", output):
        raise AssertionError(f"Expected runtime {version}, got: {output}")


def active_candidates(releases):
    number = r"(0|[1-9][0-9]*)"
    core = rf"v{number}\.{number}\.{number}"
    stable_core = (-1, -1, -1)
    candidates = []
    for release in releases:
        if release["draft"]:
            continue
        tag = release["tag_name"]
        if not release["prerelease"]:
            match = re.fullmatch(core + r"(?:\+[0-9A-Za-z.-]+)?", tag)
            if match:
                stable_core = max(stable_core, tuple(map(int, match.groups())))
        else:
            match = re.fullmatch(core + rf"-rc\.{number}", tag)
            if match:
                candidates.append((tuple(map(int, match.groups())), tag[1:]))
    # GitHub /latest can point at a backport. RC retirement follows the
    # highest stable core anywhere in release history, just like the installers.
    return [candidate for candidate in candidates if candidate[0][:3] > stable_core]


class BootstrapHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path in ("/github-api", "/github-api/latest") or self.path.startswith("/github-api?"):
            # A credential stays in this harness process. The installer sees
            # unchanged live JSON, and bundle/checksum downloads bypass us.
            try:
                data = read_bytes(API + self.path.removeprefix("/github-api"))
                status = 200
            except urllib.error.HTTPError as error:
                data, status = error.read(), error.code
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/windows":
            self.path = "/install.ps1"
        elif self.path == "/":
            self.path = "/install.sh"
        else:
            self.send_error(404)
            return
        super().do_GET()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", choices=["sh", "pwsh", "powershell"], required=True)
    parser.add_argument("--source", choices=["pr", "deployed"], default="pr")
    parser.add_argument("--packages", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    results = []

    def record(name, action):
        try:
            detail = action()
            result = {"name": name, "status": "PASS", "detail": detail}
        except Exception as error:
            result = {"name": name, "status": "FAIL", "detail": str(error)}
        results.append(result)
        print(json.dumps(result), flush=True)

    def blocked(name, reason):
        result = {"name": name, "status": "BLOCKED", "detail": reason}
        results.append(result)
        print(json.dumps(result), flush=True)

    with tempfile.TemporaryDirectory(prefix="msb-live-install-") as temporary:
        root = Path(temporary)
        env = isolated_environment(root)
        label = "macOS & Linux" if args.shell == "sh" else "Windows"
        binary = Path(env["MSB_HOME"]) / "bin" / ("msb" if args.shell == "sh" else "msb.exe")
        handler = functools.partial(BootstrapHandler, directory=str(ROOT / "scripts"))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        endpoint = f"http://127.0.0.1:{server.server_port}"
        api_transport = "direct public API"
        if args.source == "pr" and args.shell == "sh" and os.environ.get("GITHUB_TOKEN"):
            # Shared macOS runner IPs often exhaust GitHub's anonymous quota.
            # Rewrite only this repository's metadata URL to an authenticated
            # live proxy; do not replace curl for bundles or fabricate releases.
            shim = root / "transport"
            shim.mkdir()
            curl = shutil.which("curl")
            wrapper = shim / "curl"
            wrapper.write_text(
                f"#!{sys.executable}\nimport os, sys\n"
                f"args = [arg.replace({API!r}, {endpoint + '/github-api'!r}, 1) "
                f"if arg.startswith({API!r}) else arg for arg in sys.argv[1:]]\n"
                f"os.execv({curl!r}, [{curl!r}, *args])\n"
            )
            wrapper.chmod(0o755)
            env["PATH"] = str(shim) + os.pathsep + env["PATH"]
            api_transport = "authenticated live GitHub metadata proxy; direct artifact downloads"

        def run_example(section):
            code = snippet(section, label)
            if args.source == "pr":
                code = code.replace("https://install.microsandbox.dev", endpoint)
            path = root / ("example.sh" if args.shell == "sh" else "example.ps1")
            # Failures must propagate through the same pipeline/iex forms used
            # in the docs, rather than invoking extracted installer functions.
            prefix = "set -eu\n" if args.shell == "sh" else "$ErrorActionPreference = 'Stop'\n"
            path.write_text(prefix + code)
            invocation = (["sh", str(path)] if args.shell == "sh" else
                          [args.shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)])
            return command(invocation, root, env)

        def install(section, expected):
            output = run_example(section)
            version = command([str(binary), "--version"], root, env)
            assert_version(version, expected)
            command([str(binary), "--help"], root, env)
            return {"runtime": version.strip(), "installer": output[-2000:]}

        try:
            latest = read_json(API + "/latest")["tag_name"].removeprefix("v")
            releases = []
            for page in range(1, 101):
                batch = read_json(API + f"?per_page=100&page={page}")
                releases.extend(batch)
                if len(batch) < 100:
                    break
            else:
                raise RuntimeError("Release list exceeds smoke-test pagination bound")
            candidates = active_candidates(releases)
            record("exact version from docs", lambda: install("Install an exact version", "0.7.13"))
            if candidates:
                record("published RC", lambda: install("Install a release candidate", max(candidates)[1]))
            else:
                blocked("published RC installation", "No active RC is published; cannot validate successful RC installation.")

                def no_candidate():
                    before = hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None
                    try:
                        run_example("Install a release candidate")
                    except RuntimeError as error:
                        if "No active RC" not in str(error):
                            raise
                    else:
                        raise AssertionError("RC selection succeeded without an RC; possible silent stable fallback")
                    after = hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None
                    if before != after:
                        raise AssertionError("Failed RC selection changed the installed binary")
                    return "No active RC rejected; existing binary unchanged"

                record("missing RC fails closed", no_candidate)
            if args.source == "pr":
                record("flag overrides channel environment", lambda: install("Selection behavior", latest))
                record("switch to stable", lambda: install("Switching versions", latest))
        finally:
            server.shutdown()
            server.server_close()

        if args.packages:
            npm_root = root / "npm"
            npm_root.mkdir()
            npm_env = isolated_environment(npm_root)
            (npm_root / "package.json").write_text('{"name":"msb-install-smoke","private":true}')
            npm = shutil.which("npm")
            npm_tags = read_json("https://registry.npmjs.org/-/package/microsandbox/dist-tags")

            def npm_install(spec, expected, exact=False):
                command([npm, "install", *(["--save-exact"] if exact else []), "microsandbox@" + spec], npm_root, npm_env)
                package = json.loads((npm_root / "node_modules/microsandbox/package.json").read_text())
                if package["version"] != expected:
                    raise AssertionError(f"npm installed {package['version']}, expected {expected}")
                output = command(["node", str(npm_root / "node_modules/microsandbox/bin/microsandbox.cjs"), "--version"], npm_root, npm_env)
                assert_version(output, expected)
                command(["node", "--input-type=module", "-e", "await import('microsandbox'); console.log('SDK import OK')"], npm_root, npm_env)
                return {"package": package["version"], "runtime": output.strip(), "sdk_import": "OK"}

            record("npm exact package and bundled runtime", lambda: npm_install("0.7.13", "0.7.13", True))
            if "rc" in npm_tags:
                record("npm RC package and bundled runtime", lambda: npm_install("rc", npm_tags["rc"]))
            else:
                blocked("npm RC installation", "The npm rc dist-tag is not published")
            record("npm stable package and bundled runtime", lambda: npm_install("latest", npm_tags["latest"]))

            # Docker images are Linux artifacts. Verify both their downloads and
            # binary startup without privileged mode or host filesystem mounts.
            if platform.system() == "Linux":
                docker = shutil.which("docker")

                def docker_install(tag, expected):
                    image = "ghcr.io/superradcompany/microsandbox:" + tag
                    command([docker, "pull", image], root, env)
                    output = command([docker, "run", "--rm", "--network=none", image, "--version"], root, env)
                    assert_version(output, expected)
                    return output.strip()

                record("Docker exact image", lambda: docker_install("0.7.13", "0.7.13"))
                if candidates:
                    record("Docker RC image", lambda: docker_install("rc", max(candidates)[1]))
                else:
                    blocked("Docker RC installation", "No active RC is published")
                record("Docker stable image", lambda: docker_install("latest", latest))

    report = {"platform": platform.platform(), "shell": args.shell, "source": args.source,
              "api_transport": api_transport,
              "results": results, "scope": "Installation, binary startup and SDK import; no VM boot or registry publication"}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"### Real-artifact smoke: {args.source} / {args.shell}\n\n")
            for result in results:
                summary.write(f"- **{result['status']}**: {result['name']}\n")
            summary.write("\nSuccessful published RC installation remains unverified when marked BLOCKED.\n")
    return 1 if any(result["status"] == "FAIL" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
