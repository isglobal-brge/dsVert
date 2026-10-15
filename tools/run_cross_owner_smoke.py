#!/usr/bin/env python3
"""Run one v3 Linux federation smoke within a locked cumulative wall-time budget.

Example (source the R/Go environment first):
  python3 tools/run_cross_owner_smoke.py --root /workspace/dsflower \
    --label irls-b3 -- Rscript ../v3-dsVertClient/tools/validate_dp_irls_b3.R /workspace/dsflower

DSVERT_SMOKE_CAMPAIGN defaults to v3-b3. Logs and a durable JSONL event
ledger live below ROOT/.tmp/v3. Each command is capped at 900 seconds,
including cleanup; the campaign is capped at 2700 seconds across attempts.
Linux child-subreaper adoption retains ownership of detached descendants.
No process is signalled without matching its recorded /proc start time.
"""

import argparse
import ctypes
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid


MAX_COMMAND_SECONDS = 900.0
MAX_CAMPAIGN_SECONDS = 2700.0
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def accounted_seconds(events):
    """An interrupted launcher cannot make a previously reserved budget vanish."""
    attempts = {}
    for event in events:
        attempt = event["attempt_id"]
        if event["event"] == "started":
            if attempt in attempts:
                raise ValueError("duplicate smoke attempt in ledger")
            attempts[attempt] = float(event["allocated_seconds"])
        elif event["event"] == "finished":
            if attempt not in attempts:
                raise ValueError("smoke completion has no start record")
            attempts[attempt] = float(event["wall_seconds"])
        else:
            raise ValueError("unknown smoke ledger event")
    if any(not (0 <= value <= MAX_CAMPAIGN_SECONDS + 1) for value in attempts.values()):
        raise ValueError("invalid wall time in smoke ledger")
    return sum(attempts.values())


def allocate_seconds(used, command_limit, campaign_limit):
    if not (0 < command_limit <= MAX_COMMAND_SECONDS):
        raise ValueError("command timeout must be in (0, 900] seconds")
    if not (0 < campaign_limit <= MAX_CAMPAIGN_SECONDS):
        raise ValueError("campaign budget must be in (0, 2700] seconds")
    if not (0 <= used < campaign_limit):
        raise ValueError("cumulative smoke budget exhausted")
    remaining = campaign_limit - used
    return min(command_limit, remaining), (
        "campaign_budget" if remaining < command_limit else "command_limit")


def proc_identity(pid):
    """Return PID-generation identity and parent, tolerating process exit races."""
    try:
        tail = Path(f"/proc/{pid}/stat").read_text().rpartition(") ")[2].split()
        return {
            "pid": pid, "start_ticks": int(tail[19]),
            "ppid": int(tail[1]), "state": tail[0],
        }
    except (OSError, ValueError, IndexError):
        return None


class Descendants:
    def __init__(self, launcher_pid):
        self.launcher_pid = launcher_pid
        self.owned = {}

    def discover(self):
        snapshot = {}
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                value = proc_identity(int(entry.name))
                if value is not None:
                    snapshot[value["pid"]] = value
        parents = {self.launcher_pid}
        parents.update(pid for pid, start in self.owned.items()
                       if pid in snapshot and snapshot[pid]["start_ticks"] == start)
        changed = True
        while changed:
            changed = False
            for pid, value in snapshot.items():
                if pid not in parents and value["ppid"] in parents:
                    parents.add(pid)
                    self.owned[pid] = value["start_ticks"]
                    changed = True
        return self.live()

    def live(self):
        result = []
        for pid, start in self.owned.items():
            value = proc_identity(pid)
            if value is not None and value["start_ticks"] == start and value["state"] != "Z":
                result.append(pid)
        return result

    def signal_owned(self, sig):
        for pid in self.live():
            descriptor = None
            try:
                # Pin the kernel process object, then recheck its generation.
                # A PID reused after this check cannot receive the signal.
                descriptor = os.pidfd_open(pid, 0)
                value = proc_identity(pid)
                if value is not None and value["start_ticks"] == self.owned[pid]:
                    signal.pidfd_send_signal(descriptor, sig, None, 0)
            except ProcessLookupError:
                pass
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    def reap(self, primary_pid):
        for pid in self.owned:
            if pid == primary_pid:
                continue
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                pass


def enable_subreaper():
    if not sys.platform.startswith("linux") or not Path("/proc/self/stat").exists():
        raise RuntimeError("safe detached-child cleanup requires Linux /proc")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("safe PID-generation cleanup requires Python pidfd support")
    descriptor = os.pidfd_open(os.getpid(), 0)
    os.close(descriptor)
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot enable child-subreaper ownership")


def append_event(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def cleanup_owned(tracker, process, deadline):
    def quiescent():
        if tracker.live():
            return False
        # A child may have forked between the last scan and its termination.
        # Once its parent is dead, subreaper adoption makes the child visible
        # directly beneath us; rescan before declaring cleanup complete.
        process.poll()
        tracker.reap(process.pid)
        if tracker.discover():
            return False
        tracker.reap(process.pid)
        return True

    tracker.discover()
    tracker.signal_owned(signal.SIGTERM)
    grace_end = min(deadline, time.monotonic() + max(0.05, (deadline - time.monotonic()) / 3))
    while time.monotonic() < grace_end:
        process.poll()
        tracker.discover()
        tracker.reap(process.pid)
        if quiescent():
            return True
        time.sleep(min(0.025, max(0, grace_end - time.monotonic())))
    while True:
        process.poll()
        tracker.discover()
        tracker.signal_owned(signal.SIGKILL)
        tracker.reap(process.pid)
        if quiescent():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.025, max(0, deadline - time.monotonic())))


def run(args):
    if not LABEL.fullmatch(args.campaign) or not LABEL.fullmatch(args.label):
        raise ValueError("campaign and label must be safe short file-name components")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise ValueError("a command is required after --")
    root = Path(args.root).resolve(strict=True)
    state = root / ".tmp" / "v3"
    logs = state / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    ledger = state / f"{args.campaign}-smoke-ledger.jsonl"
    lock_path = state / f"{args.campaign}-smoke.lock"
    with lock_path.open("a") as lock:
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another attempt owns this campaign; concurrent smoke is refused")
        events = [json.loads(line) for line in ledger.read_text().splitlines()] if ledger.exists() else []
        used = accounted_seconds(events)
        allowance, timeout_reason = allocate_seconds(used, args.timeout, args.budget)
        enable_subreaper()
        attempt_id = uuid.uuid4().hex
        sequence = 1 + sum(event["event"] == "started" for event in events)
        log = logs / f"{args.campaign}-{args.label}-{sequence:03d}.log"
        started = time.monotonic()
        deadline = started + allowance
        cleanup_reserve = min(3.0, allowance / 5)
        run_deadline = deadline - cleanup_reserve
        cleanup_deadline = deadline - min(0.25, allowance / 20)
        start_event = {
            "event": "started", "attempt_id": attempt_id,
            "campaign": args.campaign, "label": args.label, "command": command,
            "start_utc": utc_now(), "start_monotonic": started,
            "allocated_seconds": allowance, "command_limit_seconds": args.timeout,
            "campaign_limit_seconds": args.budget, "prior_accounted_seconds": used,
            "cleanup_reserve_seconds": cleanup_reserve, "log": str(log),
        }
        append_event(ledger, start_event)
        interrupted = []
        previous_handlers = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.signal(sig, lambda number, frame: interrupted.append(number))
        environment = os.environ.copy()
        environment["DSVERT_SMOKE_CAMPAIGN"] = args.campaign
        environment["DSVERT_SMOKE_PRIOR_SECONDS"] = str(used)
        environment["DSVERT_SMOKE_ATTEMPT_SECONDS"] = str(allowance)
        tracker = Descendants(os.getpid())
        process = None
        reason = None
        launch_error = None
        clean = True
        exit_code = 125
        try:
            descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT,
                                           env=environment, start_new_session=True)
                identity = proc_identity(process.pid)
                if identity is not None:
                    tracker.owned[process.pid] = identity["start_ticks"]
                while True:
                    tracker.discover()
                    code = process.poll()
                    tracker.reap(process.pid)
                    if code is not None:
                        exit_code = code if code >= 0 else 128 - code
                        break
                    if interrupted:
                        reason = f"interrupted_{signal.Signals(interrupted[0]).name}"
                        exit_code = 128 + interrupted[0]
                        break
                    if time.monotonic() >= run_deadline:
                        reason = timeout_reason
                        exit_code = 124
                        break
                    time.sleep(min(0.05, max(0, run_deadline - time.monotonic())))
        except Exception as error:
            launch_error = f"{type(error).__name__}: {error}"
        finally:
            if process is not None:
                clean = cleanup_owned(tracker, process, cleanup_deadline)
                process.poll()
            ended = time.monotonic()
            finish = {
                **start_event, "event": "finished", "end_utc": utc_now(),
                "end_monotonic": ended, "wall_seconds": ended - started,
                "total_accounted_seconds": used + ended - started,
                "exit_code": exit_code if clean else 125,
                "command_exit_code": None if process is None else process.returncode,
                "timeout_reason": reason, "launch_error": launch_error,
                "cleanup_complete": clean, "remaining_owned_pids": tracker.live(),
                "tracked_process_count": len(tracker.owned),
            }
            append_event(ledger, finish)
            for sig, previous in previous_handlers.items():
                signal.signal(sig, previous)
        print(json.dumps(finish, sort_keys=True), flush=True)
        return finish["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", required=True, help="workspace containing v3-dsVert and v3-dsVertClient")
    parser.add_argument("--label", required=True)
    parser.add_argument("--campaign", default=os.environ.get("DSVERT_SMOKE_CAMPAIGN", "v3-b3"))
    parser.add_argument("--timeout", type=float, default=MAX_COMMAND_SECONDS)
    parser.add_argument("--budget", type=float, default=MAX_CAMPAIGN_SECONDS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Smoke launcher refused: {error}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
