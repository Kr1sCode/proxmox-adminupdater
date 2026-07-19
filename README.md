# proxmox-adminupdater

**Agentless, scheduled updates for your Proxmox LXC fleet — no SSH into the guests, no agent inside them.**

Applies **OS security patches** and runs **per-app update recipes** inside your
containers on a schedule, with a **pre-update snapshot** for one-click rollback —
all driven from a clean web UI. Think of it as scheduled `apt upgrade` + the
community-scripts "update" step, fleet-wide, without touching each guest by hand.

Sibling project to [`proxmox-autosnap`](https://github.com/Kr1sCode/proxmox-autosnap);
it reuses the same config/schedule/UI lineage.

## Why the split brain (and why there IS a host component)

Proxmox exposes **no REST API to run a command inside an LXC** — the guest-agent
`exec` exists only for QEMU VMs. So with **no SSH and no in-guest agent**, the
*only* way into a container is `pct exec` / `pct snapshot`, which are **host-side**.

adminupdater embraces that honestly and splits into two pieces:

| Component | Where | Role |
|---|---|---|
| **Brain** | unprivileged Debian 13 **LXC** | web UI, per-guest schedule, computes the plan, stores reports. Talks to PVE read-only (`VM.Audit`). |
| **Executor** | **PVE host** (~1 script + timer) | pulls the plan, `pct snapshot` + `pct exec` per job, posts results back. Stateless and dumb. |

Unlike autosnap, this **does** leave a small footprint on the host — that is
unavoidable for agentless in-guest execution. It is a single script + timer, so
it survives PVE upgrades.

## Security model

- **Host-authoritative whitelist.** A guest is touched only if its CTID is in
  `allowed_ctids` in `/etc/proxmox-adminupdater/host.conf` on the host. The LXC
  can *request*, never *force*. Starts **empty** — opt-in per container.
- **No raw commands cross the wire.** The plan carries only an **action enum**
  (`security-patch` / `app-update`) + CTID + recipe *name*. The host builds the
  actual command itself, so a compromised LXC cannot inject `rm -rf` — at worst
  it asks for a patch on a guest the host already permits. Never host root.
- **App recipes are host-trusted.** Update scripts live on the host
  (`/etc/proxmox-adminupdater/recipes/<name>.sh`) and are `pct push`ed into the
  guest at run time; the LXC only supplies the name.
- **Bearer-authed plan/report**, shared secret between LXC and host.
- **Pre-update snapshot** + optional **rollback on failure**.

## Install

Run on a Proxmox VE host:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Kr1sCode/proxmox-adminupdater/main/install.sh)"
```

It creates the LXC, provisions a read-only API token, installs the brain, and
drops the host executor + timer. Then:

1. Open `http://<container-ip>/`, log in with your Proxmox credentials.
2. Per guest: enable, pick a schedule, choose **security patches** and/or an
   **app recipe**, keep **pre-snapshot** on.
3. On the host, allow each opted-in CTID in `/etc/proxmox-adminupdater/host.conf`
   — `allowed_ctids = 101,105` for a set, or `allowed_ctids = *` to trust the
   panel. Changes apply on the **next timer tick** (no restart needed).

## End-to-end: what one scheduled run does

For a guest that is enabled, due, and allowed by the host, a single run is one
atomic unit under one rollback point:

```
① schedule           panel (Edit modal): mode + times/weekdays or interval
                     → stored per guest; the LXC computes "due" live via is_due
② plan               host timer → GET /plan → ONE job per due guest:
                       { ctid, actions:[security-patch, app-update], app, … }
③ pre-snapshot       host: pct snapshot preupd_YYYYMMDD_HHMMSS   (once)
④ detect OS          host: pct exec … cat /etc/os-release → debian|ubuntu|alpine|arch
⑤ security patches   host: pct exec …  apt-get upgrade / apk upgrade / pacman -Syu
⑥ app update         host: pct push <recipe> → pct exec …  (community-scripts `update`,
                       docker compose pull/up, …)
⑦ report             host → POST /report → LXC stores status + per-step log + history;
                       last_run set → guest no longer "due" (idempotent)
```

Ordering guarantees: **snapshot first**, then OS detection, then patches, then the
app recipe. If any step exits non-zero the chain stops; with `rollback_on_fail`
the guest is rolled back to that one pre-snapshot (the app step never runs on a
half-patched box). The host timer is the only clock.

## App recipes

Drop `<name>.sh` in `/etc/proxmox-adminupdater/recipes/` on the host and set the
guest's app recipe to `<name>` in the panel. For community-scripts containers the
recipe is usually just `update` (their in-guest helper). See
`host/recipes/example-app.sh`.

## Uninstall

```bash
bash uninstall.sh <CTID>
```

Removes the container, host executor/timer, and API token. Pre-update snapshots
in guests are left untouched.

## Layout

```
app/       core.py · adminupdater.py · web.py · static/     (runs in the LXC)
host/      executor · systemd unit + timer · recipes/       (runs on the PVE host)
systemd/   adminupdater-web.service                         (LXC)
install.sh · uninstall.sh · config/config.example.json
```

## License

MIT — see [LICENSE](LICENSE).
