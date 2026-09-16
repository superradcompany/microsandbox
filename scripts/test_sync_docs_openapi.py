"""Regression checks for public operation identifiers."""

import importlib.util
import json
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).with_name("sync-docs-openapi.py")
SPEC = importlib.util.spec_from_file_location("sync_docs_openapi", MODULE_PATH)
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


class OperationIdTests(unittest.TestCase):
    def test_resource_ids_are_stable_across_audiences(self):
        for prefix in ("/v1", "/v1/orgs/{slug}"):
            paths = {
                f"{prefix}/sandboxes/{{sandbox_id}}/volumes": {
                    "get": {"operationId": "list_volumes"}
                },
                f"{prefix}/volumes": {"get": {"operationId": "list_volumes"}},
                f"{prefix}/snapshots": {"get": {"operationId": "list"}},
                f"{prefix}/volumes/{{id}}/files": {"get": {"operationId": "list"}},
            }
            sync.qualify_operation_ids(paths)
            ids = [op["operationId"] for ops in paths.values() for op in ops.values()]
            self.assertEqual(ids, ["list_sandbox_volumes", "list_volumes",
                                   "list_snapshots", "list_directory_contents"])
            sync.qualify_operation_ids(paths)
            self.assertEqual(ids, [op["operationId"] for ops in paths.values()
                                   for op in ops.values()])

    def test_unknown_collisions_fail(self):
        with self.assertRaisesRegex(SystemExit, "duplicate operationId.*shared"):
            sync.qualify_operation_ids({
                "/v1/a": {"get": {"operationId": "shared"}},
                "/v1/b": {"get": {"operationId": "shared"}},
            })

    def test_missing_id_fails(self):
        with self.assertRaisesRegex(SystemExit, "missing operationId"):
            sync.qualify_operation_ids({"/v1/a": {"get": {}}})

    def test_checked_in_references_have_unique_ids(self):
        for name in ("openapi.json", "openapi.personal.json"):
            spec = json.loads((sync.REPO / "docs/api-reference" / name).read_text())
            ids = [op["operationId"] for ops in spec["paths"].values()
                   for op in ops.values()]
            self.assertEqual(len(ids), len(set(ids)), name)


if __name__ == "__main__":
    unittest.main()
