"""
tlv_parser.py — BER TLV parser shared by passive editor and live MITM engine.
Parses raw BER bytes into a tree of TLVNode objects.
Encodes modified trees back to bytes.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TLVNode:
    tag: int                        # numeric tag value
    tag_class: int                  # 0=universal, 1=application, 2=context, 3=private
    constructed: bool               # True = contains child TLVs
    value: bytes                    # raw value bytes (children re-encoded if constructed)
    children: list["TLVNode"] = field(default_factory=list)
    start: int = 0                  # byte offset in original buffer
    end: int = 0                    # byte offset of end in original buffer

    @property
    def tag_hex(self) -> str:
        return f"0x{self.tag:02X}"

    @property
    def length(self) -> int:
        return len(self.value)

    def decoded_value(self) -> str:
        # Best-effort human-readable decode.
        try:
            if len(self.value) == 0:
                return "(empty)"
            if len(self.value) <= 8:
                # try integer
                i = int.from_bytes(self.value, "big")
                return str(i)
            return self.value.hex()
        except Exception:
            return self.value.hex()


# ─────────────────────────────────────────────────────────────────────────────
# Tag decoding
# ─────────────────────────────────────────────────────────────────────────────

def _decode_tag(buf: bytes, offset: int) -> tuple[int, int, bool, int]:
    
    # Returns (tag_value, tag_class, is_constructed, new_offset).
    # Handles multi-byte tags.
    
    b = buf[offset]
    tag_class = (b >> 6) & 0x03
    is_constructed = bool((b >> 5) & 0x01)
    tag_num = b & 0x1F
    offset += 1

    if tag_num == 0x1F:
        # Long-form tag
        tag_num = 0
        while True:
            b = buf[offset]
            offset += 1
            tag_num = (tag_num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break

    return tag_num, tag_class, is_constructed, offset


def _decode_length(buf: bytes, offset: int) -> tuple[int, int]:
    # Returns (length_value, new_offset).
    b = buf[offset]
    offset += 1
    if b & 0x80:
        num_bytes = b & 0x7F
        if num_bytes == 0:
            raise ValueError("Indefinite-length form not supported")
        length = int.from_bytes(buf[offset:offset + num_bytes], "big")
        offset += num_bytes
    else:
        length = b
    return length, offset


# ─────────────────────────────────────────────────────────────────────────────
# Parse
# ─────────────────────────────────────────────────────────────────────────────

def parse_tlv(buf: bytes, offset: int = 0, end: int = None) -> list[TLVNode]:
    # Parse a flat list of TLV nodes from buf[offset:end].
    if end is None:
        end = len(buf)
    nodes = []
    while offset < end:
        node_start = offset
        if offset >= len(buf):
            break
        # End-of-contents marker (0x00 0x00)
        if buf[offset] == 0x00:
            offset += 1
            continue

        try:
            tag_num, tag_class, is_constructed, offset = _decode_tag(buf, offset)
            length, offset = _decode_length(buf, offset)
        except (IndexError, ValueError):
            break

        val_start = offset
        val_end = offset + length
        if val_end > len(buf):
            break

        raw_value = buf[val_start:val_end]

        node = TLVNode(
            tag=tag_num,
            tag_class=tag_class,
            constructed=is_constructed,
            value=raw_value,
            start=node_start,
            end=val_end,
        )

        if is_constructed:
            node.children = parse_tlv(raw_value, 0, length)

        nodes.append(node)
        offset = val_end

    return nodes


def parse_all(pdu_bytes: bytes) -> list[TLVNode]:
    # Parse entire PDU.
    return parse_tlv(pdu_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# Encode
# ─────────────────────────────────────────────────────────────────────────────

def _encode_tag(tag_num: int, tag_class: int, constructed: bool) -> bytes:
    is_c = 0x20 if constructed else 0x00
    first = (tag_class << 6) | is_c

    if tag_num < 0x1F:
        return bytes([first | tag_num])
    else:
        # Long-form
        result = bytes([first | 0x1F])
        encoded = []
        n = tag_num
        while n:
            encoded.append(n & 0x7F)
            n >>= 7
        encoded.reverse()
        for i, b in enumerate(encoded):
            if i < len(encoded) - 1:
                result += bytes([b | 0x80])
            else:
                result += bytes([b])
        return result


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82]) + struct.pack(">H", length)
    else:
        return bytes([0x83]) + struct.pack(">I", length)[1:]


def encode_tlv(node: TLVNode) -> bytes:
    # Re-encode a TLVNode (recursively re-encodes children if constructed).
    if node.constructed and node.children:
        value = b"".join(encode_tlv(c) for c in node.children)
    else:
        value = node.value

    tag_bytes = _encode_tag(node.tag, node.tag_class, node.constructed)
    len_bytes = _encode_length(len(value))
    return tag_bytes + len_bytes + value


def encode_all(nodes: list[TLVNode]) -> bytes:
    return b"".join(encode_tlv(n) for n in nodes)


# ─────────────────────────────────────────────────────────────────────────────
# Search & modify helpers
# ─────────────────────────────────────────────────────────────────────────────

def find_tlv_by_tag(nodes: list[TLVNode], tag: int, _results=None) -> list[TLVNode]:
    # Recursive DFS — returns all nodes matching tag (any depth).
    if _results is None:
        _results = []
    for node in nodes:
        if node.tag == tag:
            _results.append(node)
        if node.children:
            find_tlv_by_tag(node.children, tag, _results)
    return _results


def modify_tlv_value(node: TLVNode, new_value: bytes) -> None:
    # In-place value replacement. Also updates parent encoding.
    node.value = new_value
    node.children = []          # clear children — value is now raw bytes
    node.constructed = False


def all_unique_tags(nodes: list[TLVNode], _seen=None) -> list[int]:
    #Return sorted list of all unique tag numbers in the tree.
    if _seen is None:
        _seen = set()
    for node in nodes:
        _seen.add(node.tag)
        if node.children:
            all_unique_tags(node.children, _seen)
    return sorted(_seen)


def tag_occurrences(nodes: list[TLVNode], tag: int) -> list[TLVNode]:
    """All occurrences of a tag in document order."""
    return find_tlv_by_tag(nodes, tag)


def insert_tlv_between(
    nodes: list[TLVNode],
    before_tag: int, before_occ: int,
    after_tag: int, after_occ: int,
    new_node: TLVNode,
) -> list[TLVNode]:
    """
    Insert new_node after the before_occ-th occurrence of before_tag
    and before the after_occ-th occurrence of after_tag.
    Works on flat top-level list; for nested, caller must pass the right sub-list.
    Returns the new nodes list.
    """
    before_nodes = find_tlv_by_tag(nodes, before_tag)
    if before_occ - 1 >= len(before_nodes):
        raise ValueError(f"before_tag 0x{before_tag:02X} occurrence {before_occ} not found")
    after_nodes = find_tlv_by_tag(nodes, after_tag)
    if after_occ - 1 >= len(after_nodes):
        raise ValueError(f"after_tag 0x{after_tag:02X} occurrence {after_occ} not found")

    target_before = before_nodes[before_occ - 1]
    target_after = after_nodes[after_occ - 1]

    # Find positions in flat list
    try:
        idx_before = nodes.index(target_before)
        idx_after = nodes.index(target_after)
    except ValueError:
        raise ValueError("Anchors not found in top-level node list (nested not yet supported)")

    if idx_after != idx_before + 1:
        raise ValueError("Before and After anchors are not adjacent at top level")

    result = nodes[:idx_before + 1] + [new_node] + nodes[idx_after:]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# MMS / TPKT header stripping
# ─────────────────────────────────────────────────────────────────────────────

def extract_mms_pdu(tcp_payload: bytes) -> bytes | None:
  
    #Strip TPKT (4 bytes) + COTP (variable, first byte = length) headers.
    #Returns raw BER PDU bytes or None if payload too short / malformed.
    
    if len(tcp_payload) < 7:
        return None
    # TPKT: version(1) reserved(1) length(2)
    version = tcp_payload[0]
    if version != 3:
        return None
    tpkt_len = struct.unpack(">H", tcp_payload[2:4])[0]
    if tpkt_len > len(tcp_payload):
        return None
    # COTP: length indicator at byte 4
    cotp_len = tcp_payload[4] + 1   # length indicator + 1 = total COTP bytes
    pdu_start = 4 + cotp_len
    if pdu_start >= tpkt_len:
        return None
    return tcp_payload[pdu_start:tpkt_len]


def rebuild_tpkt(original_tcp_payload: bytes, new_pdu: bytes) -> bytes:

    #Re-wrap new_pdu with the same TPKT+COTP header from the original payload.
    
    cotp_len = original_tcp_payload[4] + 1
    header = original_tcp_payload[:4 + cotp_len]
    # Patch TPKT length
    new_total = len(header) + len(new_pdu)
    header = header[:2] + struct.pack(">H", new_total) + header[4:]
    return header + new_pdu
