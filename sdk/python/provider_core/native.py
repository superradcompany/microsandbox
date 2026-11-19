"""Shared wrappers retaining the native library that owns each object.

Package staging supplies the declaration schema from the existing binding stub.
No backend implementation lives here: calls, cancellation and finalization stay
with the selected native object, and results cross back through one wrapper family.
"""

import importlib
import inspect
import json
import threading

from ._schema import CLASSES, FUNCTIONS, VERSION

_loaders = {}
_loaded = {}
_owners = {}
_wrappers = {}
_full_loader = None
_full = None
_default_local = None
_lock = threading.RLock()


def register_provider(kind, module_name, version):
    if kind not in ("local", "remote"):
        raise ValueError("provider must be local or remote")
    with _lock:
        if kind in _loaders:
            raise RuntimeError(f"A {kind} microsandbox provider is already registered")
        _loaders[kind] = (module_name, version)


def register_full_provider(module_name, version):
    global _full_loader
    with _lock:
        if _full_loader is not None:
            raise RuntimeError("A full microsandbox provider is already registered")
        _full_loader = (module_name, version)


def _load(selection, kind):
    module_name, version = selection
    native = importlib.import_module(module_name)
    info = json.loads(native.provider_info())
    supported = info.get("local") and info.get("remote") if kind == "full" else info.get(kind)
    if (
        info.get("abi") != 1
        or info.get("version") != version
        or version != VERSION
        or not supported
    ):
        raise ImportError(
            f"Incompatible microsandbox {kind} provider; "
            "reinstall matching core and provider versions"
        )
    for name, wrapper in _wrappers.items():
        value = getattr(native, name, None)
        if isinstance(value, type):
            _owners[value] = (wrapper, native)
    return native


def binding(kind):
    global _full
    with _lock:
        if kind in _loaded:
            return _loaded[kind]
        if kind in _loaders:
            native = _load(_loaders[kind], kind)
            _loaded[kind] = native
            return native
        if _full is None and _full_loader is not None:
            _full = _load(_full_loader, "full")
        if _full is not None:
            return _full
    raise ImportError(f"Install and import microsandbox-{kind} before using {kind} operations")


def default_binding():
    global _default_local
    with _lock:
        kind = _mount_binding().configured_provider_kind()
        if kind == "remote":
            return binding(kind)
        if _default_local is None:
            _default_local = binding("local")
        return _default_local


def _mount_binding():
    # Mount factories construct shared MountConfig values without opening a resource.
    with _lock:
        if "remote" in _loaders and "local" not in _loaders and _full_loader is None:
            return binding("remote")
        return binding("local")


def _unwrap(value, owner):
    if isinstance(value, NativeObject):
        if value._provider is not owner:
            raise TypeError(
                "Native objects from different microsandbox providers cannot be passed "
                "to each other; use configuration values or resource references"
            )
        return value._inner
    if isinstance(value, list):
        return [_unwrap(item, owner) for item in value]
    if isinstance(value, tuple):
        return tuple(_unwrap(item, owner) for item in value)
    if isinstance(value, dict):
        return {key: _unwrap(item, owner) for key, item in value.items()}
    return value


def _wrap(value, owner, receiver=None):
    if receiver is not None and value is receiver._inner:
        return receiver
    registered = _owners.get(type(value))
    if registered is not None:
        wrapper, native = registered
        result = object.__new__(wrapper)
        object.__setattr__(result, "_inner", value)
        object.__setattr__(result, "_provider", native)
        return result
    if inspect.isawaitable(value):

        async def resolve():
            # Cancellation propagates to the original future. The wrapper never
            # turns a cancelled observation into a terminal execution outcome.
            return _wrap(await value, owner, receiver)

        return resolve()
    if isinstance(value, list):
        return [_wrap(item, owner) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap(item, owner) for item in value)
    if isinstance(value, dict):
        return {key: _wrap(item, owner) for key, item in value.items()}
    return value


def _call(function, owner, args, kwargs, receiver=None):
    return _wrap(function(*_unwrap(args, owner), **_unwrap(kwargs, owner)), owner, receiver)


class NativeType(type):
    def __getattr__(cls, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name == "ctx" and cls._native_name in ("Sandbox", "Volume", "Snapshot"):
            collection = {"Sandbox": "sandboxes", "Volume": "volumes", "Snapshot": "snapshots"}[
                cls._native_name
            ]
            return lambda context: getattr(context, collection)

        def invoke(*args, **kwargs):
            if (
                name in ("local", "remote")
                and cls._native_name in ("Sandbox", "Volume", "Snapshot")
            ):
                owner = binding(name)
            elif cls._native_name == "Volume" and name in (
                "bind", "named", "owned", "tmpfs", "disk",
            ):
                owner = _mount_binding()
            else:
                owner = default_binding()
            function = getattr(getattr(owner, cls._native_name), name)
            return _call(function, owner, args, kwargs)

        invoke.__name__ = name
        return invoke


class NativeObject(metaclass=NativeType):
    __slots__ = ("_inner", "_provider")

    def __new__(cls, *args, **kwargs):
        owner = None
        if cls._native_name == "Context":
            base = args[1] if len(args) > 1 else kwargs.get("base")
            if base is not None:
                if not isinstance(base, NativeObject):
                    raise TypeError("base must be a retained native context")
                # Derive through its original provider even if registrations changed.
                owner = base._provider
            else:
                owner = binding(json.loads(args[0])["kind"])
        else:
            owner = default_binding()
        result = object.__new__(cls)
        object.__setattr__(result, "_provider", owner)
        object.__setattr__(
            result,
            "_inner",
            getattr(owner, cls._native_name)(*_unwrap(args, owner), **_unwrap(kwargs, owner)),
        )
        return result

    def __init__(self, *args, **kwargs):
        # Construction is in __new__, matching the existing context subclasses.
        pass

    def __getattr__(self, name):
        value = getattr(self._inner, name)
        if callable(value):

            def invoke(*args, **kwargs):
                return _call(value, self._provider, args, kwargs, self)

            invoke.__name__ = name
            return invoke
        return _wrap(value, self._provider, self)

    def __setattr__(self, name, value):
        setattr(self._inner, name, _unwrap(value, self._provider))

    def __repr__(self):
        return repr(self._inner)


def _protocol(name):
    def invoke(self, *args, **kwargs):
        return _call(getattr(self._inner, name), self._provider, args, kwargs, self)

    invoke.__name__ = name
    return invoke


for _name, _protocols in CLASSES.items():
    _attributes = {"_native_name": _name, "__module__": __package__, "__slots__": ()}
    _attributes.update({name: _protocol(name) for name in _protocols})
    _wrappers[_name] = NativeType(_name, (NativeObject,), _attributes)
    globals()[_name] = _wrappers[_name]
BranchOutcome = _wrappers["ForkOutcome"]


def __getattr__(name):
    if name not in FUNCTIONS:
        raise AttributeError(name)
    if name == "version":
        return lambda: VERSION

    def invoke(*args, **kwargs):
        owner = default_binding()
        return _call(getattr(owner, name), owner, args, kwargs)

    invoke.__name__ = name
    return invoke
