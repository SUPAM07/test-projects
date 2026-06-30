"""
redis_ts.py — Redis TimeSeries integration for AIUS v1.0
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from typing import Any, Optional

logger = logging.getLogger("redis_ts")

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

_client: Optional[Any] = None
_server_proc: Optional[subprocess.Popen] = None

_RETENTION_MS = 3_600_000  # 1 hour


# ─────────────────────────────────────────────────────────────
# SERVER MANAGEMENT
# ─────────────────────────────────────────────────────────────

def _find_binary():
    return shutil.which("redis-stack-server") or shutil.which("redis-server")


def _ping(host, port):
    try:
        r = redis.StrictRedis(host=host, port=port, socket_connect_timeout=1)
        r.ping()
        return True
    except Exception:
        return False


def _start_server(host, port):
    global _server_proc

    binary = _find_binary()
    if not binary:
        return False, "Redis not installed"

    cmd = [binary, "--port", str(port)]

    try:
        _server_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        return False, f"Start failed: {e}"

    # wait for startup
    for _ in range(30):
        time.sleep(0.1)
        if _ping(host, port):
            return True, f"Started Redis (pid={_server_proc.pid})"

    return False, "Redis start timeout"


def stop_server():
    global _server_proc
    if _server_proc:
        try:
            _server_proc.terminate()
            _server_proc.wait(timeout=3)
        except Exception:
            pass
        _server_proc = None


# ─────────────────────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────────────────────

def connect(host="127.0.0.1", port=6379, password=None):
    global _client

    if not REDIS_AVAILABLE:
        return False, "Install redis-py: pip install redis[hiredis]"

    if not _ping(host, port):
        ok, msg = _start_server(host, port)
        if not ok:
            return False, msg

    try:
        _client = redis.StrictRedis(
            host=host,
            port=port,
            password=password,
            decode_responses=False,
        )
        _client.ping()
    except Exception as e:
        _client = None
        return False, f"Connect failed: {e}"

    # Check TimeSeries
    try:
        _client.execute_command("TS.INFO", "test_key")
        ts_ok = True
    except Exception as e:
        if "unknown command" in str(e).lower():
            ts_ok = False
        else:
            ts_ok = True

    if ts_ok:
        return True, f"✓ Redis connected ({host}:{port}) [TimeSeries OK]"
    else:
        return True, f"⚠ Redis connected but NO TimeSeries"


def disconnect():
    global _client
    _client = None


def is_connected():
    if not _client:
        return False
    try:
        _client.ping()
        return True
    except Exception:
        return False


def get_client():
    return _client


# ─────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────

def _ts_create(key):
    try:
        _client.execute_command(
            "TS.CREATE",
            key,
            "RETENTION",
            _RETENTION_MS,
            "DUPLICATE_POLICY",
            "LAST",
        )
    except Exception:
        pass


def _hex_to_float(h):
    try:
        b = bytes.fromhex(h)
        return float(int.from_bytes(b, "big")) if b else 0.0
    except Exception:
        return 0.0


# ─────────────────────────────────────────────────────────────
# WRITE LIVE DATA
# ─────────────────────────────────────────────────────────────

def write_packet_to_redis(record, flow_id="default"):
    if not is_connected():
        return

    ts = record.get("ts_ms", int(time.time() * 1000))
    seq = record.get("seq", 0)

    try:
        _client.set(f"mms:index:{seq}", json.dumps(record), ex=3600)
    except Exception as e:
        logger.debug(f"index error: {e}")

    def walk(tlvs):
        for t in tlvs:
            tag = t.get("tag", "0x00")
            val = _hex_to_float(t.get("value_hex", ""))
            length = t.get("len", 0)

            vk = f"mms:{flow_id}:{tag}:value"
            lk = f"mms:{flow_id}:{tag}:length"

            _ts_create(vk)
            _ts_create(lk)

            try:
                _client.execute_command("TS.ADD", vk, ts, val)
                _client.execute_command("TS.ADD", lk, ts, length)
            except Exception as e:
                logger.debug(f"TS.ADD fail {vk}: {e}")

            if "children" in t:
                walk(t["children"])

    walk(record.get("tlv", []))


# ─────────────────────────────────────────────────────────────
# OLD PCAP STORAGE
# ─────────────────────────────────────────────────────────────

def store_old_pcap_values(records):
    if not is_connected():
        return "[Redis] Not connected"

    stored = 0

    for r in records:
        ts = int(r.get("ts_ms", time.time() * 1000))

        def walk(tlvs):
            nonlocal stored
            for t in tlvs:
                try:
                    tag = t.get("tag", "0x00")
                    val = _hex_to_float(t.get("value_hex", ""))

                    key = f"old:{tag}:value"
                    _ts_create(key)

                    _client.execute_command("TS.ADD", key, ts, val)
                    stored += 1
                except Exception:
                    pass

                if "children" in t:
                    walk(t["children"])

        walk(r.get("tlv", []))

    return f"[Redis] Old PCAP stored: {stored} values"


def get_old_value(tag):
    if not is_connected():
        return None

    try:
        res = _client.execute_command("TS.GET", f"old:{tag}:value")
        if res:
            val = int(float(res[1]))
            l = max(1, (val.bit_length() + 7) // 8)
            return val.to_bytes(l, "big")
    except Exception:
        pass

    return None

def list_live_tags(flow_id: str = "default") -> list[str]:
    if not is_connected():
        return []
    try:
        prefix = f"mms:{flow_id}:".encode()
        suffix = b":value"
        return sorted(
            k[len(prefix):-len(suffix)].decode()
            for k in _client.keys(f"mms:{flow_id}:*:value")
            if k.startswith(prefix) and k.endswith(suffix)
        )
    except Exception as e:
        logger.debug(f"list_live_tags: {e}")
        return []

# ─────────────────────────────────────────────────────────────
# UTIL
# ─────────────────────────────────────────────────────────────

def flush_live_data(flow_id="default"):
    if not is_connected():
        return "Not connected"

    try:
        keys = _client.keys(f"mms:{flow_id}:*")
        if keys:
            _client.delete(*keys)
        return f"Flushed {len(keys)} keys"
    except Exception as e:
        return f"Error: {e}"
