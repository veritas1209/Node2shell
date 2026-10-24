#!/usr/bin/env python3
"""Measure the constrained chain across bounded local service scenarios.

Every trial starts a fresh read-only container with ASLR enabled.  The only
RCE proof remains a fresh loopback token followed by fixed `/usr/bin/id`.
No debugger, process address read, preload library, arbitrary command, or
non-loopback target is available through this runner.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time


ROOT = Path(__file__).parents[1]
EVIDENCE_DIR = ROOT / "evidence" / "runtime-scenarios"
DEFAULT_VERSIONS = ("22.23.3", "24.22.0", "26.12.0")
RUNTIME_IMAGES = {
    "debian12": "node2shell-nonce-local:matrix",
    "ubuntu2404": "node2shell-worker-runtime:ubuntu-24.04",
}
SCENARIOS = {
    "debian-baseline": {
        "runtime": "debian12",
        "server_profile": "baseline",
        "heap_noise_blocks": 0,
        "background_connections": 0,
        "fragment_size": 0,
    },
    "debian-observed-noise": {
        "runtime": "debian12",
        "server_profile": "observed",
        "heap_noise_blocks": 8,
        "background_connections": 0,
        "fragment_size": 257,
    },
    "debian-socket-concurrent": {
        "runtime": "debian12",
        "server_profile": "socket-tuned",
        "heap_noise_blocks": 0,
        "background_connections": 2,
        "fragment_size": 97,
    },
    "ubuntu-baseline": {
        "runtime": "ubuntu2404",
        "server_profile": "baseline",
        "heap_noise_blocks": 0,
        "background_connections": 0,
        "fragment_size": 0,
    },
    "ubuntu-observed-noise": {
        "runtime": "ubuntu2404",
        "server_profile": "observed",
        "heap_noise_blocks": 8,
        "background_connections": 0,
        "fragment_size": 257,
    },
    "ubuntu-socket-concurrent": {
        "runtime": "ubuntu2404",
        "server_profile": "socket-tuned",
        "heap_noise_blocks": 0,
        "background_connections": 2,
        "fragment_size": 97,
    },
}


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = load("n2s_runtime_matrix", ROOT / "tools" / "verify_aslr_network_matrix.py")


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_attempt(
    binary: Path,
    profile,
    scenario_name: str,
    scenario: dict[str, object],
    timeout: float,
) -> dict[str, object]:
    started = time.monotonic()
    runtime: dict[str, object] = {}
    try:
        runtime = MATRIX.start_container(
            binary,
            profile.record_size,
            server_profile=str(scenario["server_profile"]),
            heap_noise_blocks=int(scenario["heap_noise_blocks"]),
            image=RUNTIME_IMAGES[str(scenario["runtime"])],
        )
        MATRIX.HEAP.wait_ready()
        proof = MATRIX.HEAP.attack(
            profile,
            timeout,
            background_connections=int(scenario["background_connections"]),
            fragment_size=int(scenario["fragment_size"]),
        )
        return {
            "scenario": scenario_name,
            "outcome": "rce-proof",
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "proof_token": proof["proof_token"],
            "proof_stdout": proof["proof_stdout"],
            "runtime": runtime,
        }
    except Exception as error:
        logs = MATRIX.docker("logs", "--tail", "30", MATRIX.CONTAINER, check=False)
        return {
            "scenario": scenario_name,
            "outcome": "not-verified",
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "error": f"{type(error).__name__}: {error}",
            "container_log_tail": logs.stdout[-3000:],
            "runtime": runtime,
        }
    finally:
        MATRIX.stop_container()


def run_trial(
    binary: Path,
    profile,
    scenario_name: str,
    scenario: dict[str, object],
    timeout: float,
    attempts_per_trial: int,
) -> dict[str, object]:
    attempts = []
    for attempt in range(1, attempts_per_trial + 1):
        result = run_attempt(binary, profile, scenario_name, scenario, timeout)
        result["attempt"] = attempt
        attempts.append(result)
        if result["outcome"] == "rce-proof":
            break
    return {
        "scenario": scenario_name,
        "outcome": (
            "rce-proof" if attempts[-1]["outcome"] == "rce-proof" else "not-verified"
        ),
        "first_attempt_success": attempts[0]["outcome"] == "rce-proof",
        "attempt_count": len(attempts),
        "attempts": attempts,
    }


def verify_version(
    version: str,
    scenario_names: list[str],
    trials: int,
    timeout: float,
    attempts_per_trial: int,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(
        prefix=f"runtime-v{version}-", dir=MATRIX.WORK_PARENT
    ) as temporary:
        binary, archive_sha, archive_url = MATRIX.DIRECT.fetch_official_binary(
            version, Path(temporary)
        )
        analysis = MATRIX.DIRECT.ANALYZER.extract(binary)
        symbols = MATRIX.static_symbols(binary)
        candidates = MATRIX.layout_candidates(str(analysis["node_binary_sha256"]))
        candidate = candidates[0]
        if candidate["selection"] != "verified-binary-fingerprint":
            raise RuntimeError(
                "official binary did not match the verified fingerprint registry"
            )
        profile, _, _ = MATRIX.derive_profile(binary, version, candidate)
        results: list[dict[str, object]] = []
        for scenario_name in scenario_names:
            scenario = SCENARIOS[scenario_name]
            for trial in range(1, trials + 1):
                print(
                    f"RUNTIME version={version} scenario={scenario_name} "
                    f"trial={trial}/{trials}",
                    flush=True,
                )
                result = run_trial(
                    binary,
                    profile,
                    scenario_name,
                    scenario,
                    timeout,
                    attempts_per_trial,
                )
                result["trial"] = trial
                results.append(result)
                print(
                    f"RUNTIME version={version} scenario={scenario_name} "
                    f"trial={trial}/{trials} outcome={result['outcome']}",
                    flush=True,
                )
        scenario_summary = {}
        for scenario_name in scenario_names:
            selected = [item for item in results if item["scenario"] == scenario_name]
            successes = sum(item["outcome"] == "rce-proof" for item in selected)
            first_attempt_successes = sum(
                bool(item["first_attempt_success"]) for item in selected
            )
            total_attempts = sum(int(item["attempt_count"]) for item in selected)
            scenario_summary[scenario_name] = {
                "successes": successes,
                "trials": len(selected),
                "success_rate": successes / len(selected),
                "first_attempt_successes": first_attempt_successes,
                "first_attempt_success_rate": first_attempt_successes / len(selected),
                "total_attempts": total_attempts,
                "successful_attempts": successes,
                "per_attempt_success_rate": successes / total_attempts,
            }
        return {
            "version": version,
            "node_binary_sha256": analysis["node_binary_sha256"],
            "official_archive_sha256": archive_sha,
            "official_archive_url": archive_url,
            "selected_profile": MATRIX.public_profile(profile, symbols, candidate),
            "scenarios": {name: SCENARIOS[name] for name in scenario_names},
            "attempts_per_trial": attempts_per_trial,
            "scenario_summary": scenario_summary,
            "trials": results,
            "lab_controls": {
                "target": "127.0.0.1:3000",
                "callback": "127.0.0.1:4444",
                "proof_command": "/usr/bin/id (fixed)",
                "aslr": "enabled",
                "debugger_used": False,
                "address_read_used": False,
                "ld_preload_used": False,
            },
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }


def write_summary(versions: list[str], scenario_names: list[str]) -> dict[str, object]:
    records = [
        json.loads((EVIDENCE_DIR / f"{version}.json").read_text(encoding="utf-8"))
        for version in versions
    ]
    by_scenario = {}
    for scenario_name in scenario_names:
        successes = sum(
            record["scenario_summary"][scenario_name]["successes"]
            for record in records
        )
        trials = sum(
            record["scenario_summary"][scenario_name]["trials"]
            for record in records
        )
        first_attempt_successes = sum(
            record["scenario_summary"][scenario_name]["first_attempt_successes"]
            for record in records
        )
        total_attempts = sum(
            record["scenario_summary"][scenario_name]["total_attempts"]
            for record in records
        )
        by_scenario[scenario_name] = {
            "successes": successes,
            "trials": trials,
            "success_rate": successes / trials,
            "first_attempt_successes": first_attempt_successes,
            "first_attempt_success_rate": first_attempt_successes / trials,
            "total_attempts": total_attempts,
            "successful_attempts": successes,
            "per_attempt_success_rate": successes / total_attempts,
        }
    total_successes = sum(item["successes"] for item in by_scenario.values())
    total_trials = sum(item["trials"] for item in by_scenario.values())
    total_first_attempt_successes = sum(
        item["first_attempt_successes"] for item in by_scenario.values()
    )
    total_attempts = sum(item["total_attempts"] for item in by_scenario.values())
    summary = {
        "versions": versions,
        "scenario_names": scenario_names,
        "by_scenario": by_scenario,
        "total_successes": total_successes,
        "total_trials": total_trials,
        "overall_success_rate": total_successes / total_trials,
        "first_attempt_successes": total_first_attempt_successes,
        "first_attempt_success_rate": total_first_attempt_successes / total_trials,
        "total_attempts": total_attempts,
        "per_attempt_success_rate": total_successes / total_attempts,
        "complete": total_successes == total_trials,
        "verification_mode": "aslr-on-network-only-runtime-scenario-benchmark",
        "debugger_used": False,
        "address_read_used": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json(EVIDENCE_DIR / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="append", help="exact affected release")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS))
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--attempts-per-trial", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="rebuild the summary from existing per-version evidence",
    )
    args = parser.parse_args()
    if not 1 <= args.trials <= 20:
        parser.error("--trials must be between 1 and 20")
    if not 1 <= args.attempts_per_trial <= 5:
        parser.error("--attempts-per-trial must be between 1 and 5")
    if not 3.0 <= args.timeout <= 30.0:
        parser.error("--timeout must be between 3 and 30 seconds")
    MATRIX.WORK_PARENT.mkdir(parents=True, exist_ok=True)
    official = MATRIX.DIRECT.official_scope()
    versions = args.version or list(DEFAULT_VERSIONS)
    unknown = sorted(set(versions) - set(official), key=MATRIX.DIRECT.semver)
    if unknown:
        parser.error("outside official affected scope: " + ", ".join(unknown))
    scenario_names = args.scenario or list(SCENARIOS)
    if args.summary_only:
        missing = [
            version for version in versions if not (EVIDENCE_DIR / f"{version}.json").exists()
        ]
        if missing:
            parser.error("missing per-version evidence: " + ", ".join(missing))
        summary = write_summary(versions, scenario_names)
        print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
        return 0 if summary["complete"] else 1
    for version in versions:
        record = verify_version(
            version,
            scenario_names,
            args.trials,
            args.timeout,
            args.attempts_per_trial,
        )
        save_json(EVIDENCE_DIR / f"{version}.json", record)
    summary = write_summary(versions, scenario_names)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 0 if summary["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
