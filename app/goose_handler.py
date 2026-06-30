from scapy.all import Ether
from tlv_parser1 import parse_all, pretty_print, encode_tlv

def extract_goose_pdu(frame_bytes):

    offset = 14   # Ethernet header

    # Skip VLAN if present
    ethertype = int.from_bytes(frame_bytes[12:14], "big")

    if ethertype == 0x8100:
        offset += 4

    # Skip GOOSE header
    offset += 8

    return frame_bytes[offset:]

def handle_goose(pkt):

    raw = bytes(pkt)

    try:
        goose_pdu = extract_goose_pdu(raw)
        
        print(f"\nGOOSE Packet: {pkt[Ether].src}  →  {pkt[Ether].dst}")
        print("\n===== GOOSE PDU HEX =====")
        print(goose_pdu.hex())

        tlvs = parse_all(goose_pdu)
        pretty_print(tlvs)

    except Exception as e:
        print("GOOSE parser error:", e)
