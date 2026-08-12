#!/usr/bin/env python3
"""Guard against the 2026-08-09 incident: a partial inventory scan (3 of 18
guests) passed as "populated" and let GUARD 0 in compute_plan() prune every
other guest's real schedule. Run: python3 app/test_adminupdater.py"""

import os
import tempfile

tmp = tempfile.mkdtemp()
os.environ["ADMINUPDATER_CONFIG"] = os.path.join(tmp, "config.json")
os.environ["ADMINUPDATER_STATE"] = os.path.join(tmp, "state.json")
os.environ["ADMINUPDATER_LOG"] = os.path.join(tmp, "log")

import core          # noqa: E402  (paths must be set before import)
import adminupdater as up  # noqa: E402

FULL = {"guests": {str(v): {"name": f"g{v}", "type": "lxc"} for v in range(1, 19)}}


def test_partial_scan_rejected():
    up.set_inventory(FULL)
    assert len(up.get_inventory()["guests"]) == 18
    r = up.set_inventory({"guests": {"1": FULL["guests"]["1"], "2": FULL["guests"]["2"]}})
    assert r == {"ok": False, "kept": True}
    assert len(up.get_inventory()["guests"]) == 18, "partial scan must not clobber good inventory"


def test_empty_scan_rejected():
    r = up.set_inventory({"guests": {}})
    assert r == {"ok": False, "kept": True}
    assert len(up.get_inventory()["guests"]) == 18


def test_growing_scan_accepted():
    bigger = {"guests": dict(FULL["guests"], **{"19": {"name": "g19", "type": "lxc"}})}
    r = up.set_inventory(bigger)
    assert r == {"ok": True}
    assert len(up.get_inventory()["guests"]) == 19


def test_new_guest_auto_enrolled_and_backup_never_blocks():
    cfg = core.load_config()
    core.save_config(cfg)
    up.compute_plan()
    cfg = core.load_config()
    assert cfg["guests"]["19"]["enabled"] is True
    # a guest with no fresh backup at all must still get its update job -- the
    # pre_snapshot is the rollback point, "no backup" is informational only now
    import datetime as dt
    due_time = (dt.datetime.now() - dt.timedelta(minutes=5)).strftime("%H:%M")
    cfg["guests"]["19"]["times"] = [due_time]
    cfg["guests"]["19"]["weekdays"] = []
    core.save_config(cfg)
    jobs = up.compute_plan()
    assert any(j.get("kind") == "update" and j.get("ctid") == 19 for j in jobs)


def test_gone_guest_pruned():
    cfg = core.load_config()
    cfg["guests"]["999"] = dict(up.GUEST_DEFAULTS, enabled=True)
    core.save_config(cfg)
    up.compute_plan()
    cfg = core.load_config()
    assert "999" not in cfg["guests"]


if __name__ == "__main__":
    test_partial_scan_rejected()
    test_empty_scan_rejected()
    test_growing_scan_accepted()
    test_new_guest_auto_enrolled_and_backup_never_blocks()
    test_gone_guest_pruned()
    print("OK")
