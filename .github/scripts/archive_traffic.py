#!/usr/bin/env python3
"""Append today's GitHub traffic (views/clones) to .github/traffic/*.csv.

GitHub's Insights -> Traffic view only keeps a rolling 14-day window and
never exposes it publicly. Run by .github/workflows/traffic-stats.yml on a
daily schedule so the history survives past that window. Idempotent: never
duplicates a date already present in the CSV.
"""
import csv
import json
import os
import subprocess
import sys

REPO = os.environ["GITHUB_REPOSITORY"]
KINDS = ("views", "clones")


def existing_dates(path):
    if not os.path.exists(path):
        return set()
    with open(path, newline="", encoding="utf-8") as f:
        return {row[0] for row in csv.reader(f) if row and row[0] != "date"}


def main():
    os.makedirs(".github/traffic", exist_ok=True)
    for kind in KINDS:
        path = f".github/traffic/{kind}.csv"
        is_new = not os.path.exists(path)
        seen = existing_dates(path)
        out = subprocess.run(
            ["gh", "api", f"repos/{REPO}/traffic/{kind}"],
            check=True, capture_output=True, text=True,
        ).stdout
        data = json.loads(out)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if is_new:
                w.writerow(["date", "count", "uniques"])
            for entry in data.get(kind, []):
                date = entry["timestamp"][:10]
                if date not in seen:
                    w.writerow([date, entry["count"], entry["uniques"]])
                    seen.add(date)


if __name__ == "__main__":
    sys.exit(main())
