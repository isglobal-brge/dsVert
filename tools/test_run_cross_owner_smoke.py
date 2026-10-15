"""Focused launcher checks; no R, federation or native MPC execution."""

import importlib.util
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("run_cross_owner_smoke.py")
SPEC = importlib.util.spec_from_file_location("smoke_launcher", SCRIPT)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class BudgetTests(unittest.TestCase):
    def test_finished_time_and_unfinished_reservation_count_once(self):
        events = [
            {"event": "started", "attempt_id": "a", "allocated_seconds": 900},
            {"event": "finished", "attempt_id": "a", "wall_seconds": 12.5},
            {"event": "started", "attempt_id": "b", "allocated_seconds": 900},
        ]
        self.assertEqual(smoke.accounted_seconds(events), 912.5)
        self.assertEqual(smoke.allocate_seconds(2698, 900, 2700), (2, "campaign_budget"))
        self.assertEqual(smoke.allocate_seconds(10, 900, 2700), (900, "command_limit"))
        for values in [(2700, 900, 2700), (0, 901, 2700), (0, 900, 2701)]:
            with self.assertRaises(ValueError):
                smoke.allocate_seconds(*values)


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux subreaper")
class ProcessTests(unittest.TestCase):
    def invoke(self, root, label, code, timeout=2, budget=10):
        return subprocess.run([
            sys.executable, str(SCRIPT), "--root", str(root), "--campaign", "test-campaign",
            "--label", label, "--timeout", str(timeout), "--budget", str(budget), "--",
            sys.executable, "-c", code,
        ], capture_output=True, text=True, timeout=8)

    def test_timeout_reaps_detached_double_fork_and_preserves_unrelated_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "detached.pid"
            unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
            try:
                code = f"""
import os, signal, time
from pathlib import Path
child = os.fork()
if child == 0:
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path({str(marker)!r}).write_text(str(os.getpid()))
    time.sleep(20)
    os._exit(0)
time.sleep(20)
"""
                result = self.invoke(root, "detached-timeout", code)
                self.assertEqual(result.returncode, 124, result.stderr + result.stdout)
                record = json.loads(result.stdout)
                self.assertEqual(record["timeout_reason"], "command_limit")
                self.assertTrue(record["cleanup_complete"])
                self.assertEqual(record["remaining_owned_pids"], [])
                self.assertLess(record["wall_seconds"], 2.2)
                self.assertGreaterEqual(record["tracked_process_count"], 2)
                self.assertIsNone(smoke.proc_identity(int(marker.read_text())))
                self.assertIsNone(unrelated.poll(), "unrelated process was signalled")
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=3)

    def test_success_cleans_detached_child_and_records_environment_and_times(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "child.pid"
            code = f"""
import os, time
from pathlib import Path
print(os.environ['DSVERT_SMOKE_CAMPAIGN'], flush=True)
if os.fork() == 0:
    os.setsid()
    Path({str(marker)!r}).write_text(str(os.getpid()))
    time.sleep(20)
    os._exit(0)
while not Path({str(marker)!r}).exists():
    time.sleep(0.01)
"""
            result = self.invoke(root, "success", code)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            record = json.loads(result.stdout)
            self.assertIsNone(record["timeout_reason"])
            self.assertTrue(record["cleanup_complete"])
            self.assertEqual(record["wall_seconds"], record["end_monotonic"] - record["start_monotonic"])
            self.assertIn("+00:00", record["start_utc"])
            self.assertIn("+00:00", record["end_utc"])
            self.assertEqual(Path(record["log"]).read_text().strip(), "test-campaign")
            self.assertIsNone(smoke.proc_identity(int(marker.read_text())))
            events = [json.loads(line) for line in (root / ".tmp/v3/test-campaign-smoke-ledger.jsonl").read_text().splitlines()]
            self.assertEqual(len(events), 2)
            self.assertEqual(smoke.accounted_seconds(events), record["wall_seconds"])

    def test_active_campaign_and_exhausted_reservation_refuse_new_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / ".tmp/v3"
            state.mkdir(parents=True)
            marker = root / "must-not-run"
            code = f"from pathlib import Path; Path({str(marker)!r}).touch()"
            with (state / "test-campaign-smoke.lock").open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = self.invoke(root, "concurrent", code)
                self.assertEqual(result.returncode, 125)
                self.assertIn("another attempt owns", result.stderr)
            (state / "test-campaign-smoke-ledger.jsonl").write_text(json.dumps({
                "event": "started", "attempt_id": "interrupted-launcher",
                "allocated_seconds": 10,
            }) + "\n")
            result = self.invoke(root, "exhausted", code)
            self.assertEqual(result.returncode, 125)
            self.assertIn("budget exhausted", result.stderr)
            self.assertFalse(marker.exists())

    def test_campaign_remaining_time_bounds_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.invoke(Path(directory), "remaining", "import time; time.sleep(20)",
                                 timeout=2, budget=0.6)
            self.assertEqual(result.returncode, 124, result.stderr + result.stdout)
            record = json.loads(result.stdout)
            self.assertEqual(record["timeout_reason"], "campaign_budget")
            self.assertEqual(record["allocated_seconds"], 0.6)
            self.assertTrue(record["cleanup_complete"])
            self.assertLess(record["wall_seconds"], 0.8)


if __name__ == "__main__":
    unittest.main()
