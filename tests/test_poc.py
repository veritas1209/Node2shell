import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "poc" / "node2shell_lab.py"
SPEC = importlib.util.spec_from_file_location("node2shell_lab", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PocTests(unittest.TestCase):
    def test_trigger_fingerprint(self):
        trigger = MODULE.malformed_brotli(b"")
        self.assertEqual(hashlib.sha256(trigger).hexdigest(), MODULE.TRIGGER_SHA256)

    def test_stage_one_is_fixed_to_proof_program(self):
        stage = MODULE.build_stage_one(MODULE.Profile.load())
        self.assertNotIn(b"/bin/sh", stage)
        self.assertNotIn(b"/usr/bin/id", stage)

    def test_verifier_requires_matching_process_token_and_id(self):
        token = b"a" * 32
        response = b"N2S-PROOF:" + token + b"\nuid=1000(node) gid=1000(node)\n"
        self.assertIsNotNone(MODULE.verify(response, token))
        self.assertIsNone(MODULE.verify(response, b"b" * 32))
        self.assertIsNone(MODULE.verify(b"N2S-PROOF:" + token, token))
        self.assertEqual(MODULE.classify_response(response, MODULE.verify(response, token)), "rce-proof")
        self.assertEqual(MODULE.classify_response(b"", None), "connection-closed-or-crash")

    def test_stage_two_keeps_expected_corruption_fields(self):
        stage = MODULE.build_stage_two(0x137ED748, 256)
        self.assertEqual(stage[7], 8)
        self.assertEqual(stage[15:19], bytes.fromhex("48d77e13"))
        self.assertEqual(stage[19:27], bytes.fromhex("ffffff7fffffff7f"))

    def test_matrix_artifacts_cover_every_official_linux_x64_release(self):
        profile_paths = sorted((ROOT / "poc" / "profiles").glob("*.json"))
        evidence_paths = sorted(
            path
            for path in (ROOT / "evidence" / "matrix").glob("*.json")
            if path.name != "summary.json"
        )
        self.assertEqual(len(profile_paths), 84)
        self.assertEqual(
            [path.stem for path in profile_paths],
            [path.stem for path in evidence_paths],
        )
        self.assertEqual(
            {major: sum(path.stem.startswith(f"{major}.") for path in profile_paths)
             for major in (22, 24, 26)},
            {22: 36, 24: 30, 26: 18},
        )

        sha256 = re.compile(r"[0-9a-f]{64}")
        for profile_path, evidence_path in zip(profile_paths, evidence_paths):
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["chain_version"], 4, profile_path.name)
            self.assertEqual(profile["pivot_mode"], "saved_rbp_leave", profile_path.name)
            self.assertEqual(profile["target"], "127.0.0.1:3000", profile_path.name)
            self.assertEqual(evidence["version"], profile_path.stem, evidence_path.name)
            self.assertEqual(evidence["result"], "rce-verified", evidence_path.name)
            self.assertEqual(evidence["proof_channel"], "exploited HTTP request socket")
            self.assertRegex(evidence["official_archive_sha256"], sha256)
            self.assertRegex(evidence["node_binary_sha256"], sha256)
            self.assertEqual(
                evidence["node_binary_sha256"], profile["node_binary_sha256"]
            )
            MODULE.build_stage_one(MODULE.Profile(profile))

        summary = json.loads(
            (ROOT / "evidence" / "matrix" / "summary.json").read_text(encoding="utf-8")
        )
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["official_affected_linux_x64_release_count"], 84)
        self.assertEqual(summary["rce_verified_count"], 84)
        self.assertEqual(summary["failed_or_unverified"], {})


if __name__ == "__main__":
    unittest.main()
