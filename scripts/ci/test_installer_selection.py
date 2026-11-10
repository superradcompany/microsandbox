"""Adversarial metadata fixtures for the dependency-free Unix JSON resolver."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="msb-selection-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "functions.sh"
        source = INSTALLER.read_text()
        self.assertTrue(source.endswith('main "$@"\n'))
        self.source.write_text(source.removesuffix('main "$@"\n'))

    def call(self, function, payload="", *args):
        return subprocess.run(["sh", "-c", '. "$1"; shift; "$@"', "test", str(self.source), function, *args],
                              input=payload, text=True, capture_output=True, timeout=5)

    def test_structural_json_parser_ignores_notes_and_nested_assets(self):
        release = {"tag_name": "v0.8.0-rc.1", "draft": False, "prerelease": True,
                   "body": 'text: "tag_name":"v99.0.0-rc.1" \\ {} \n\t ☃',
                   "assets": [{"tag_name": "v99.0.0-rc.1", "draft": True}],
                   "nested": [None, 1.2e-30, True, {}, []]}
        for indent in [None, 2]:
            result = self.call("release_records", json.dumps([release], indent=indent))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "v0.8.0-rc.1 false true\n#1\n")

    def test_large_release_response_and_chunk_boundaries(self):
        # Real GitHub responses include megabytes of notes and nested assets.
        # Keep this compact so strings and escapes also cross parser chunks.
        releases = [{"tag_name": f"v0.8.0-rc.{index}", "draft": False, "prerelease": True,
                     "body": ("Unicode ☃, quotes \" and backslash \\ \n" * 140),
                     "assets": [{"tag_name": "v99.0.0-rc.1"}]}
                    for index in range(200)]
        payload = json.dumps(releases, ensure_ascii=False)
        self.assertGreater(len(payload), 1_000_000)
        result = self.call("release_records", payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = "".join(f"v0.8.0-rc.{index} false true\n" for index in range(200)) + "#200\n"
        self.assertEqual(result.stdout, expected)

    def test_malformed_metadata_fails_closed(self):
        for data in ['{}', 'null', '[', '[{}]', '[false]', '[] trailing', '[{},]',
                     '[{"tag_name":"v0.8.0-rc.1","draft":"false","prerelease":true}]',
                     '[{"tag_name":"v0.8.0-rc.1","draft":false,"draft":true,"prerelease":true}]',
                     '[{"tag_name":"v0.8.0-rc.1","draft":false,"prerelease":true,"body":"\\q"}]',
                     '[{"tag_name":"v0.8.0-rc.1","draft":false,"prerelease":true,"body":01}]']:
            with self.subTest(data=data):
                self.assertNotEqual(self.call("release_records", data).returncode, 0)

    def test_empty_release_list(self):
        result = self.call("release_records", '[]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '#0\n')

    def test_semver_numbers_do_not_use_floating_point_comparison(self):
        result = self.call("select_rc", 'v0.8.0-rc.9007199254740992 false true\n'
                           'v0.8.0-rc.9007199254740993 false true\n')
        self.assertEqual(result.stdout, 'v0.8.0-rc.9007199254740993\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unrecognized_candidates_are_not_selected(self):
        for tag in ['v0.8.0-beta.1', 'v0.8.0-rc.01', 'v00.8.0-rc.1', 'v0.8.0-rc1']:
            self.assertNotEqual(self.call('select_rc', f'{tag} false true\n').returncode, 0)

    def test_bad_versions_are_rejected_before_url_construction(self):
        for version in ['0.8.0\n0.9.0', '0.8.0/evil', '0.8.0-rc..1', '0.8.0-rc.01', ' 0.8.0']:
            self.assertNotEqual(self.call('normalize_version', '', version).returncode, 0)
        for version in ['0.8.0-rc.1', 'v0.8.0-rc.1', '0.8.0+build.1']:
            result = self.call('normalize_version', '', version)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'v' + version.removeprefix('v') + '\n')

    def test_api_failure_does_not_fall_back(self):
        curl = self.root / 'curl'
        curl.write_text('#!/bin/sh\nexit 22\n')
        curl.chmod(0o755)
        result = subprocess.run(['sh', '-c', '. "$1"; VERSION=""; CHANNEL=rc; resolve_version',
                                 'test', str(self.source)], text=True, capture_output=True, timeout=5,
                                env={**os.environ, 'PATH': str(self.root) + ':/usr/bin:/bin'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Could not list RC releases', result.stderr)


class LiveSmokeSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        smoke = runpy.run_path(str(Path(__file__).with_name("test-live-release-install.py")))
        cls.select = staticmethod(smoke["active_candidates"])

    @staticmethod
    def release(tag, prerelease=False, draft=False):
        return {"tag_name": tag, "prerelease": prerelease, "draft": draft}

    def test_backport_does_not_reactivate_retired_candidate(self):
        releases = [self.release("v0.7.14"), self.release("v0.8.0+build.1"),
                    self.release("v0.8.0-rc.1", True)]
        self.assertEqual(self.select(releases), [])
        self.assertEqual(self.select(list(reversed(releases))), [])

    def test_canonical_candidates_and_draft_stable_releases(self):
        releases = [self.release("v0.8.0"), self.release("v0.7.14"),
                    self.release("v1.0.0", draft=True)]
        releases += [self.release(tag, True) for tag in
                     ["v0.9.0-rc.9", "v0.9.0-rc.10", "v0.9.0-rc.01", "v0.9.0-beta.1"]]
        releases += [self.release("v0.10.0-rc.1", True, True), self.release("v0.10.0-rc.2")]
        self.assertEqual(max(self.select(releases))[1], "0.9.0-rc.10")
        self.assertEqual(len(self.select(releases)), 2)

    def test_candidate_before_first_stable_release(self):
        self.assertEqual(self.select([self.release("v0.0.0-rc.1", True)]),
                         [((0, 0, 0, 1), "0.0.0-rc.1")])


if __name__ == '__main__':
    unittest.main()
