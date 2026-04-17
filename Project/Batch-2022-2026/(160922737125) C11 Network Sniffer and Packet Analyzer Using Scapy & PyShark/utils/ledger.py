import os
import json
import hashlib
from typing import Any, Dict, List

from utils.helpers import get_ledger_path


def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_chain() -> List[Dict[str, Any]]:
    ledger_path = get_ledger_path()
    if not os.path.exists(ledger_path):
        return []

    with open(ledger_path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []


def save_chain(chain: List[Dict[str, Any]]) -> None:
    ledger_path = get_ledger_path()
    os.makedirs(os.path.dirname(ledger_path), exist_ok=True)

    with open(ledger_path, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2)


def add_record_to_chain(record: Dict[str, Any]) -> str:
    chain = load_chain()
    previous_hash = chain[-1]["current_hash"] if chain else "GENESIS"

    payload = json.dumps(record, sort_keys=True)
    current_hash = compute_hash(previous_hash + payload)

    chain_entry = {
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "record": record
    }

    chain.append(chain_entry)
    save_chain(chain)
    return current_hash