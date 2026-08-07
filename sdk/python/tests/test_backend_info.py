from microsandbox import default_backend_info, default_backend_kind


def test_default_backend_info_is_structured_and_secret_safe() -> None:
    info = default_backend_info()

    assert info.kind in {"local", "cloud"}
    assert info.kind == default_backend_kind()
    assert not hasattr(info, "api_key")
    if info.kind == "cloud":
        assert info.api_url.startswith(("http://", "https://"))
    else:
        assert info.api_url is None
