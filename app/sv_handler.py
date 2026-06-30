from scapy.all import Ether
from tlv_parser1 import parse_all, pretty_print, encode_tlv

def extract_sv_pdu(frame_bytes):

    offset = 14

    ethertype = int.from_bytes(frame_bytes[12:14], "big")

    if ethertype == 0x8100:
        offset += 4

    offset += 8

    return frame_bytes[offset:]
    
def handle_sv(pkt):

    raw = bytes(pkt)

    try:
        sv_pdu = extract_sv_pdu(raw)
        
        print(f"\nSV Packet: {pkt[Ether].src}  →  {pkt[Ether].dst}")
        print("\n===== SV PDU HEX =====")
        print(sv_pdu.hex())

        tlvs = parse_all(sv_pdu)
        pretty_print(tlvs)

    except Exception as e:
        print("SV parser error:", e)
