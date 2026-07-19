#!/usr/bin/env bash
# Host-trusted app update recipe. Runs INSIDE the target guest as root (pushed
# there by the executor via `pct push`). Name it <app>.sh and set the guest's
# `app_update` value to <app> in the panel.
#
# Exit non-zero on failure -> the host may roll back the pre-snapshot.
set -euo pipefail

# community-scripts containers ship an `update` helper in the guest:
if command -v update >/dev/null 2>&1; then
    update
    exit $?
fi

# docker-compose app example:
# cd /opt/myapp
# docker compose pull
# docker compose up -d
# docker image prune -f

echo "brak zdefiniowanej metody aktualizacji dla tego kontenera" >&2
exit 1
