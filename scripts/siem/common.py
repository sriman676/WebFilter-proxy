"""Shared helpers for the SIEM scripts (stdlib only): schema fields, timestamps, JSONL loading."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTIONS = ROOT / "siem" / "opensearch" / "detections.json"
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def request_fields():
    """Request-event keys, read from the authoritative table in docs/LOG_SCHEMA.md."""
    text = (ROOT / "docs" / "LOG_SCHEMA.md").read_text(encoding="utf-8")
    table = text.split("## Request event", 1)[1].split("\n## ", 1)[0]
    fields = []
    for line in table.splitlines():
        cell = line.split("|")[1] if line.startswith("|") else ""
        fields += re.findall(r"`([a-z0-9_]+)`", cell)
    return fields


def fmt_ts(dt):
    return dt.astimezone(timezone.utc).strftime(TS_FORMAT)[:-3] + "Z"


def parse_ts(s):
    return datetime.strptime(s.rstrip("Z"), TS_FORMAT).replace(tzinfo=timezone.utc)


def load_jsonl(directory):
    """Every event from webfilter*.jsonl in `directory`, including rotated `.N` files."""
    events = []
    for path in sorted(Path(directory).glob("webfilter*.jsonl*")):
        if path.name.endswith(".jsonl") or re.search(r"\.jsonl\.\d+$", path.name):
            with path.open(encoding="utf-8") as f:
                events += [json.loads(line) for line in f if line.strip()]
    return events


def load_detections():
    return json.loads(DETECTIONS.read_text(encoding="utf-8"))["detections"]
