"""Recognize visible TLS records and supported QUIC long headers."""
import struct


def tls(data):
    if len(data) < 5:
        return None
    kind, version, size = struct.unpack_from("!BHH", data)
    if kind not in (20, 21, 22, 23) or version not in (0x301, 0x302, 0x303) or not 0 < size <= 16640:
        return None
    if kind == 22 and len(data) >= 9 and data[5] not in (1, 2, 4, 8, 11, 12, 13, 14, 15, 16, 20, 24):
        return None
    fields = {"记录类型": {20:"ChangeCipherSpec",21:"Alert",22:"Handshake",23:"Application Data"}[kind],
              "记录版本": hex(version), "记录长度": size}
    if kind == 22 and len(data) >= 9 and data[5] in (1, 2):
        fields["可见握手类型"] = "ClientHello" if data[5] == 1 else "ServerHello"
    return fields


def quic(data):
    if len(data) < 7 or data[0] & 0xc0 != 0xc0:
        return None
    version = int.from_bytes(data[1:5], "big")
    if version not in (1, 0x6b3343cf):
        return None
    dest = data[5]
    if dest > 20 or 6 + dest >= len(data):
        return None
    source = data[6 + dest]
    end = 7 + dest + source
    if source > 20 or end >= len(data):
        return None
    kinds = ("Initial", "0-RTT", "Handshake", "Retry") if version == 1 else ("Retry", "Initial", "0-RTT", "Handshake")
    return {"版本": hex(version), "长报文类型": kinds[(data[0] >> 4) & 3],
            "目标连接ID": data[6:6+dest].hex(), "源连接ID": data[7+dest:end].hex()}

