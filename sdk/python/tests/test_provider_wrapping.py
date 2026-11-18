"""Wrapper-only regression tests; no native payload or runtime is needed."""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def wrappers(monkeypatch):
    package = ModuleType("_provider_test_core")
    package.__path__ = []
    schema = ModuleType("_provider_test_core._schema")
    schema.VERSION = "test"
    schema.CLASSES = {"Sandbox": ["__aenter__", "__aexit__"], "ForkOutcome": [], "Volume": [],
                      "ExecHandle": ["__aiter__", "__anext__"], "ExecOutput": [], "Context": []}
    schema.FUNCTIONS = ["version"]
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, schema.__name__, schema)
    path = Path(__file__).parents[1] / "provider_core/native.py"
    spec = importlib.util.spec_from_file_location("_provider_test_core._native", path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)

    def register(kind, version="test"):
        native = ModuleType(f"_provider_test_{kind}")
        native.configured_provider_kind = lambda: "local"
        native.provider_info = lambda: json.dumps({"abi": 1, "version": version, kind: True})

        class Output:
            def __init__(self, status):
                self.status = status

        class Execution:
            def __init__(self):
                self.events = [b"output", 7]
                self.completion = None
                self.ready = asyncio.Event()

            async def wait(self):
                if self.completion is None:
                    await self.ready.wait()
                    self.completion = 7
                return self.completion

            def __aiter__(self):
                return self

            async def __anext__(self):
                if not self.events:
                    raise StopAsyncIteration
                return self.events.pop(0)

        class Sandbox:
            def __init__(self):
                self.id = kind

            @staticmethod
            async def get(name):
                return Sandbox()

            def echo(self, value):
                return value

            def execution(self):
                return Execution()

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

        native.Sandbox, native.ExecOutput, native.ExecHandle = Sandbox, Output, Execution
        monkeypatch.setitem(sys.modules, native.__name__, native)
        module.register_provider(kind, native.__name__, "test")
        return native

    return module, register


@pytest.mark.asyncio
async def test_wrapped_results_retain_provider_and_protocols(wrappers):
    core, register = wrappers
    local = register("local")
    sb = await core.Sandbox.get("task")
    remote = register("remote")
    core.binding("remote")
    assert isinstance(sb, core.Sandbox)
    assert sb.id == "local"
    assert sb._provider is local
    assert sb.echo(sb) is sb
    async with sb as borrowed:
        assert borrowed is sb
    execution = sb.execution()
    assert isinstance(execution, core.ExecHandle)
    assert [event async for event in execution] == [b"output", 7]
    foreign = core._wrap(remote.Sandbox(), remote)
    with pytest.raises(TypeError, match="different microsandbox providers"):
        sb.echo(foreign)


@pytest.mark.asyncio
async def test_cancelled_wrapper_wait_does_not_record_completion(wrappers):
    core, register = wrappers
    register("local")
    sb = await core.Sandbox.get("task")
    execution = sb.execution()
    pending = asyncio.create_task(execution.wait())
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await pending
    assert execution._inner.completion is None
    execution._inner.ready.set()
    assert await execution.wait() == await execution.wait() == 7


def test_provider_version_rejected_before_resource_construction(wrappers):
    core, register = wrappers
    register("local", version="incompatible")
    with pytest.raises(ImportError, match="matching core and provider versions"):
        core.binding("local")


def test_context_derivation_keeps_its_original_provider(wrappers, monkeypatch):
    core, register = wrappers
    native = register("remote")

    class NativeContext:
        def __init__(self, options, base=None):
            self.options = json.loads(options)
            self.base = base

    native.Context = NativeContext
    base = core.Context('{"kind":"remote","apiKey":"fixture"}')

    def unexpected_selection(*_):
        raise AssertionError("derivation must not select a provider again")

    monkeypatch.setattr(core, "binding", unexpected_selection)
    derived = core.Context('{"url":"https://derived.example"}', base)
    assert derived._provider is native
    assert derived._inner.base is base._inner
    assert derived._inner.options == {"url": "https://derived.example"}


def test_remote_only_volume_mount_factories_do_not_select_local_resources(wrappers):
    core, register = wrappers
    remote = register("remote")
    factories = {"bind": ("/src",), "named": ("data",), "owned": (), "tmpfs": (), "disk": ("/img",)}
    remote.Volume = type("Volume", (), {
        name: staticmethod(lambda *args, **kwargs: (args, kwargs)) for name in factories
    })
    for name, args in factories.items():
        assert getattr(core.Volume, name)(*args, readonly=True) == (args, {"readonly": True})

    with pytest.raises(ImportError, match="microsandbox-local"):
        core.Volume.get("data")
