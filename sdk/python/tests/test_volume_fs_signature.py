import inspect

from microsandbox._microsandbox import VolumeFs


def test_copy_and_rename_expose_usable_source_keywords() -> None:
    for method in (VolumeFs.copy, VolumeFs.rename):
        parameters = inspect.signature(method).parameters

        assert tuple(parameters) == ("self", "from_", "to")
        assert parameters["from_"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
