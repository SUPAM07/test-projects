"""
json_writer.py — Converts intercepted MMS packets to JSON and appends to
live_packets.json with fcntl.flock() for thread-safe writes from the NFQueue
callback thread.

Schema per packet:
{
  "seq":    int,
  "ts_ms":  int,          # epoch milliseconds
  "src_ip": str,
  "dst_ip": str,
  "sport":  int,
  "dport":  int,
  "tlv": [
    {"tag": "0xNN", "len": int, "value_hex": str, "constructed": bool}, ...
  ]
}
"""

from __future__ import annotations
import json
import time
import fcntl
import os
from pathlib import Path
from typing import Optional

from tlv_parser2 import extract_mms_pdu, parse_all, TLVNode

_DEFAULT_PATH = Path("live_packets.json")
_seq_counter = 0


# ─────────────────────────────────────────────────────────────────────────────
# TLV node → flat dict list
# ─────────────────────────────────────────────────────────────────────────────

def _tlv_nodes_to_dicts(nodes: list[TLVNode], depth: int = 0) -> list[dict]:
    result = []
    for node in nodes:
        entry = {
            "tag": node.tag_hex,
            "len": node.length,
            "value_hex": node.value.hex(),
            "constructed": node.constructed,
            "depth": depth,
        }
        if node.children:
            entry["children"] = _tlv_nodes_to_dicts(node.children, depth + 1)
        result.append(entry)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main converter
# ─────────────────────────────────────────────────────────────────────────────

def pkt_to_json(raw_payload: bytes, src_ip: str, dst_ip: str,
                sport: int, dport: int) -> Optional[dict]:
    
    #Parse a raw TCP payload to a JSON-serialisable dict.
    #Returns None if payload is not a valid MMS/TPKT frame.
    
    global _seq_counter

    pdu = extract_mms_pdu(raw_payload)
    if pdu is None:
        return None

    try:
        nodes = parse_all(pdu)
    except Exception:
        return None

    if not nodes:
        return None

    _seq_counter += 1

    return {
        "seq":    _seq_counter,
        "ts_ms":  int(time.time() * 1000),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport":  sport,
        "dport":  dport,
        "tlv":    _tlv_nodes_to_dicts(nodes),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Thread-safe append writer
# ─────────────────────────────────────────────────────────────────────────────

def append_to_json_store(record: dict,
                         path: Path = _DEFAULT_PATH) -> None:
    #Append one JSON record (one line) to live_packets.json with file lock.
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with open(path, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            fh.write(line)
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def load_json_store(path: Path = _DEFAULT_PATH) -> list[dict]:
    #Load all records from live_packets.json (newline-delimited JSON).
    if not path.exists():
        return []
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def clear_json_store(path: Path = _DEFAULT_PATH) -> None:
    #Truncate live_packets.json (called on each new MITM session start).
    with open(path, "w") as fh:
        fh.truncate(0)


# ─────────────────────────────────────────────────────────────────────────────
# Extract unique tags from JSON records (for GUI dropdown population)
# ─────────────────────────────────────────────────────────────────────────────

def _flatten_tlv(tlv_list: list[dict]) -> list[dict]:
    flat = []
    for t in tlv_list:
        flat.append(t)
        if "children" in t:
            flat.extend(_flatten_tlv(t["children"]))
    return flat


def unique_tags_from_records(records: list[dict]) -> list[str]:
    #Return sorted unique tag hex strings from a list of JSON records.
    seen = set()
    for rec in records:
        for tlv in _flatten_tlv(rec.get("tlv", [])):
            seen.add(tlv["tag"])
    return sorted(seen)


def occurrences_of_tag(records: list[dict], tag_hex: str) -> list[int]:
    # For a given tag, return occurrence indices across all records
    
    count = 0
    for rec in records:
        for tlv in _flatten_tlv(rec.get("tlv", [])):
            if tlv["tag"] == tag_hex:
                count += 1
    return list(range(1, count + 1))
