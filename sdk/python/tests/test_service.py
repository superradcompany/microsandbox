"""Service results and change outcomes pass through from the native SDK unchanged."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

from microsandbox import ServiceTarget

FIXTURES = (
    Path(__file__).resolve().parents[3] / "packages/microsandbox-types/rust/lib/cloud/fixtures"
)


def test_service_target_repr_shows_sandbox_and_port() -> None:
    assert repr(ServiceTarget("web", 8080)) == "ServiceTarget(sandbox='web', port=8080)"


def test_service_calls_surface_native_results_and_outcomes(tmp_path: Path) -> None:
    # A fresh process isolates the SDK's process-wide backend; every request goes to a local fake.
    env = os.environ.copy()
    env["MSB_HOME"] = str(tmp_path)
    env["MSB_CONFIG_PATH"] = str(tmp_path / "test-config.json")
    env["SERVICE_FIXTURES"] = str(FIXTURES)
    for key in ("MSB_PROFILE", "MSB_BACKEND"):
        env.pop(key, None)
    script = textwrap.dedent(
        """
        import asyncio
        import json
        import os
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pathlib import Path

        from microsandbox import (
            BackendKind, ChangeState, CloudHttpError, InvalidConfigError, Service,
            ServiceError, ServiceErrorReason, ServiceNotFoundError, ServiceStatus,
            ServiceTarget, UnsupportedError,
            set_default_backend,
        )

        fixtures = Path(os.environ["SERVICE_FIXTURES"])
        scenario = json.loads((fixtures / "service-binding-scenario.json").read_text())
        extra = {
            "PATCH /v1/services/shop": {
                "status": 422,
                "body": {
                    "error": {
                        "code": "slug_reserved",
                        "message": "slug is reserved",
                        "details": None,
                    }
                },
            },
            "POST /v1/services/shop/disable": {
                "status": 503,
                "headers": {"Retry-After": "Fri, 01 Jan 2100 00:00:00 GMT"},
                "body": {
                    "error": {
                        "code": "service_changes_paused",
                        "message": "Service changes are paused. Try again in a few minutes.",
                        "details": None,
                    }
                },
            },
        }
        answers = {**scenario["answers"], **extra}

        def reply_body(answer):
            if "body_fixture" in answer:
                return (fixtures / answer["body_fixture"]).read_text()
            return json.dumps(answer["body"]) if "body" in answer else ""

        requests = []

        class Fake(BaseHTTPRequestHandler):
            def answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode()
                route = f"{self.command} {self.path}"
                requests.append((route, body))
                reply = answers.get(route, {"status": 404})
                answer = reply_body(reply)
                self.send_response(reply["status"])
                self.send_header("Content-Type", "application/json")
                for name, value in reply.get("headers", {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer.encode())

            do_GET = do_POST = do_PATCH = do_DELETE = answer

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        async def main():
            url = f"http://127.0.0.1:{server.server_address[1]}"
            set_default_backend(BackendKind.CLOUD, url=url, api_key="test")

            svc = await Service.create("shop", target=ServiceTarget("web-1", 8080))
            assert svc.url == "https://shop.<domain>"
            assert svc.status is ServiceStatus.ENABLED
            assert svc.target == ServiceTarget("web-1", 8080)

            try:
                await svc.enable()
            except ServiceError as error:
                assert error.slug == "shop"
                assert error.reason is ServiceErrorReason.TARGET_UNREACHABLE
                assert error.retry_after == 5.0
                assert error.changed is ChangeState.UNCHANGED
                assert error.raw_code is None
                assert error.raw_status is None
                assert error.raw_message is None
            else:
                raise AssertionError("unreachable enable reported success")

            try:
                await svc.remove()
            except ServiceError as error:
                assert error.reason is ServiceErrorReason.OUTCOME_UNKNOWN
                assert error.changed is ChangeState.UNKNOWN
            else:
                raise AssertionError("lost remove reported success")

            try:
                await Service.get("gone")
            except ServiceNotFoundError as error:
                assert error.changed is None
            else:
                raise AssertionError("expected ServiceNotFoundError")

            try:
                await Service.create("shop", target=None)
            except InvalidConfigError as error:
                assert error.changed is ChangeState.UNCHANGED
            else:
                raise AssertionError("expected InvalidConfigError")

            try:
                svc.update()
            except TypeError:
                pass
            else:
                raise AssertionError("expected TypeError")

            try:
                await svc.update(target=None)
            except InvalidConfigError as error:
                assert error.changed is ChangeState.UNCHANGED
            else:
                raise AssertionError("expected InvalidConfigError")

            try:
                await svc.update(target=ServiceTarget("web-2", 8080))
            except ServiceError as error:
                assert error.reason is ServiceErrorReason.OTHER
                assert error.raw_code == "slug_reserved"
                assert error.raw_status == 422
                assert error.raw_message == "slug is reserved"
                assert error.changed is ChangeState.UNCHANGED
            else:
                raise AssertionError("unrecognized refusal reported success")

            try:
                await svc.disable()
            except ServiceError as error:
                assert error.reason is ServiceErrorReason.SERVICE_CHANGES_PAUSED
                assert error.retry_after is not None and error.retry_after > 0
                assert error.changed is ChangeState.UNCHANGED
            else:
                raise AssertionError("paused disable reported success")

            extra_requests = [
                {
                    "route": "PATCH /v1/services/shop",
                    "body": {"target": {"sandbox": "web-2", "port": 8080}},
                },
                {"route": "POST /v1/services/shop/disable"},
            ]
            expected = [*scenario["requests"], *extra_requests]
            assert [route for route, _ in requests] == [r["route"] for r in expected]
            for (route, body), want in zip(requests, expected):
                if "body" in want:
                    assert json.loads(body) == want["body"], route

            set_default_backend(BackendKind.LOCAL)
            try:
                await svc.enable()
            except ServiceError as error:
                assert error.reason is ServiceErrorReason.TARGET_UNREACHABLE
            else:
                raise AssertionError("Service handle did not keep its cloud backend")

            try:
                await Service.get("shop")
            except UnsupportedError as error:
                assert error.changed is None
            else:
                raise AssertionError("local Service lookup reported success")

            try:
                await Service.list()
            except UnsupportedError as error:
                assert error.changed is None
            else:
                raise AssertionError("local Service list reported success")

            try:
                await Service.create(
                    "shop", target=ServiceTarget("web-1", 8080)
                )
            except UnsupportedError as error:
                assert error.changed is ChangeState.UNCHANGED
            else:
                raise AssertionError("local Service creation reported success")

        asyncio.run(main())
        server.shutdown()
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
