#!/usr/bin/env python3
"""Guard the self-update report race: a job can target the brain's own
container, whose web server may not be listening yet right after its own
reboot step. post_report() must retry instead of losing the result outright.
Run: python3 host/test_proxmox_adminupdater_exec.py"""

import importlib.util
import os
import sys
import time

spec = importlib.util.spec_from_file_location(
    "adminupdater_exec",
    os.path.join(os.path.dirname(__file__), "proxmox-adminupdater-exec.py"))
exe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exe)
exe.time.sleep = lambda s: None  # don't actually wait in tests


def test_retries_then_succeeds():
    calls = {"n": 0}

    def flaky_http(cfg, path, method="GET", body=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionRefusedError("mózg jeszcze nie wstał")
        return {}

    exe.http = flaky_http
    ok = exe.post_report({}, [{"status": "ok"}], attempts=5, delay=0)
    assert ok is True
    assert calls["n"] == 3


def test_gives_up_after_max_attempts():
    calls = {"n": 0}

    def always_fails(cfg, path, method="GET", body=None):
        calls["n"] += 1
        raise ConnectionRefusedError("mózg dalej nie wstał")

    exe.http = always_fails
    ok = exe.post_report({}, [{"status": "ok"}], attempts=3, delay=0)
    assert ok is False
    assert calls["n"] == 3


def test_first_try_success_no_retry():
    calls = {"n": 0}

    def works(cfg, path, method="GET", body=None):
        calls["n"] += 1
        return {}

    exe.http = works
    ok = exe.post_report({}, [{"status": "ok"}], attempts=5, delay=0)
    assert ok is True
    assert calls["n"] == 1


# --- QemuDriver.exec: a single flaky guest-exec-status QMP query must not fail
# the whole job -- observed live on a Windows VM busy running Windows Update
# ("qga command 'guest-exec-status' failed - got timeout") while the launched
# process was still completing fine in the guest. ---

def test_qemu_exec_retries_status_query_then_succeeds():
    calls = {"n": 0}

    def fake_run(cmd, timeout):
        if "--synchronous" in cmd:
            return 0, '{"pid": 42}'
        assert cmd[:3] == ["qm", "guest", "exec-status"]
        calls["n"] += 1
        if calls["n"] < 3:
            return 1, "qga command 'guest-exec-status' failed - got timeout"
        return 0, '{"exited": true, "exitcode": 0, "out-data": "done"}'

    exe.run = fake_run
    rc, out = exe.QemuDriver(201).exec(["echo", "hi"], 60)
    assert (rc, out) == (0, "done")
    assert calls["n"] == 3


def test_qemu_exec_unconfirmed_after_repeated_query_failures():
    def fake_run(cmd, timeout):
        if "--synchronous" in cmd:
            return 0, '{"pid": 42}'
        return 1, "qga command 'guest-exec-status' failed - got timeout"

    exe.run = fake_run
    rc, out = exe.QemuDriver(201).exec(["echo", "hi"], 60)
    assert rc == 124  # unconfirmed, not a real command failure
    assert "3x" in out


def test_qemu_exec_launch_failure_is_a_real_failure():
    exe.run = lambda cmd, timeout: (1, "qm guest exec nieudany (rc=1)")
    rc, out = exe.QemuDriver(201).exec(["echo", "hi"], 60)
    assert rc == 1  # never even started -- not the ambiguous "lost confirmation" case


# --- _step_verdict: rc==124 (lost confirmation) must never trigger a rollback,
# since the guest-side action may have completed successfully. ---

def test_step_verdict_124_is_unconfirmed_and_never_rolls_back():
    called = {"n": 0}
    exe.rollback = lambda driver, snap, timeout: called.__setitem__("n", called["n"] + 1) or True
    verdict = exe._step_verdict(124, "preupd_x", {"rollback_on_fail": True}, None, 60)
    assert verdict == "unconfirmed"
    assert called["n"] == 0


def test_step_verdict_real_failure_still_rolls_back():
    exe.rollback = lambda driver, snap, timeout: True
    verdict = exe._step_verdict(1, "preupd_x", {"rollback_on_fail": True}, None, 60)
    assert verdict == "rolled-back"


def test_long_backup_learns_capped_window():
    """A 558-min Saturday run must learn an 8h window, not fall back to 3h: the
    old `smin + 180` made a LONGER backup produce a SHORTER window, and the 03:30
    jobs walked into a still-running vzdump ("VM is locked (backup)")."""
    st = int(time.mktime((2026, 8, 29, 23, 0, 0, 0, 0, -1)))   # a Saturday
    exe._node_name = lambda: "node"
    exe._recent_vzdump_tasks = lambda node: [{"starttime": st, "endtime": st + 558 * 60}]
    w = exe.learn_windows([{"id": "sat", "schedule": "sat 23:00"}])
    assert w["sat"] == (1380, (1380 + 480) % 1440), w          # 23:00 -> 07:00


if __name__ == "__main__":
    test_retries_then_succeeds()
    test_gives_up_after_max_attempts()
    test_first_try_success_no_retry()
    test_qemu_exec_retries_status_query_then_succeeds()
    test_qemu_exec_unconfirmed_after_repeated_query_failures()
    test_qemu_exec_launch_failure_is_a_real_failure()
    test_step_verdict_124_is_unconfirmed_and_never_rolls_back()
    test_step_verdict_real_failure_still_rolls_back()
    test_long_backup_learns_capped_window()
    print("OK")
