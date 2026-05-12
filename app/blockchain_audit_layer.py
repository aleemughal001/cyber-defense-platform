import os
import json
import hashlib
import threading
from datetime import datetime

LEDGER_FILE = os.getenv("AUDIT_LEDGER_FILE", "/data/audit_ledger.jsonl")
_lock = threading.Lock()


def _ensure_ledger_dir():
    ledger_dir = os.path.dirname(LEDGER_FILE)
    if ledger_dir:
        os.makedirs(ledger_dir, exist_ok=True)


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _get_previous_hash() -> str:
    if not os.path.exists(LEDGER_FILE):
        return "GENESIS"

    try:
        with open(LEDGER_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            return "GENESIS"

        last_entry = json.loads(lines[-1])
        return last_entry.get("current_hash", "GENESIS")
    except Exception:
        return "GENESIS"


def append_audit_record(event_type: str, payload: dict) -> dict:
    _ensure_ledger_dir()

    with _lock:
        previous_hash = _get_previous_hash()

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
        }

        record_string = _canonical_json(entry)
        current_hash = hashlib.sha256(record_string.encode("utf-8")).hexdigest()
        entry["current_hash"] = current_hash

        with open(LEDGER_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry
