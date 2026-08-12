#!/usr/bin/env python3
"""Guard the self-update report race: a job can target the brain's own
container, whose web server may not be listening yet right after its own
reboot step. post_report() must retry instead of losing the result outright.
Run: python3 host/test_proxmox_adminupdater_exec.py"""

import importlib.util
import os
import sys

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


if __name__ == "__main__":
    test_retries_then_succeeds()
    test_gives_up_after_max_attempts()
    test_first_try_success_no_retry()
    print("OK")
