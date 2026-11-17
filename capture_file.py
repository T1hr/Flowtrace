"""Classic PCAP reader/writer with integer timestamps and original frame lengths."""
from dataclasses import dataclass
import struct


MAX_FRAME = 262144
MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1),
}


@dataclass(frozen=True)
class Frame:
    ns: int
    link: int
    wire: int
    raw: bytes


def exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("PCAP 数据截断")
    return data


def read_pcap(stream, ready=lambda link: None):
    magic = exact(stream, 4)
    if magic not in MAGIC:
        raise ValueError("需要标准 PCAP 文件")
    order, scale = MAGIC[magic]
    major, minor, _, _, snap, link = struct.unpack(order + "HHIIII", exact(stream, 20))
    if (major, minor) != (2, 4) or not snap:
        raise ValueError("不支持的 PCAP 文件头")
    link &= 0xffff
    ready(link)
    while prefix := stream.read(1):
        sec, sub, captured, wire = struct.unpack(order + "IIII", prefix + exact(stream, 15))
        if captured > min(snap, MAX_FRAME, wire) or sub * scale >= 10**9:
            raise ValueError("PCAP 帧长度或时间戳非法")
        yield Frame(sec * 10**9 + sub * scale, link, wire, exact(stream, captured))


def write_pcap_header(stream, link):
    stream.write(struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, MAX_FRAME, link))


def write_frame(stream, frame):
    sec, nanos = divmod(frame.ns, 10**9)
    stream.write(struct.pack("<IIII", sec, nanos, len(frame.raw), frame.wire))
    stream.write(frame.raw)

