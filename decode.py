"""Bounded protocol parsing. Layer offsets are relative to the original frame."""
from dataclasses import dataclass, field
from ipaddress import ip_address
import re
import struct
from protocol_meta import quic, tls


@dataclass
class Layer:
    name: str
    start: int
    end: int
    fields: dict


@dataclass
class Packet:
    frame: object
    layers: list = field(default_factory=list)
    protocols: set = field(default_factory=set)
    src: str = ""
    dst: str = ""
    sport: int | None = None
    dport: int | None = None
    seq: int = 0
    ack: int = 0
    flags: int = 0
    payload_length: int = 0
    payload_offset: int = 0
    owners: tuple = (None, None)
    summary: str = ""
    error: str = ""

    @property
    def protocol(self):
        return self.layers[-1].name if self.layers else "未知"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mac(data):
    return data.hex(":")


def decode(frame):
    p = Packet(frame)
    data = frame.raw
    end = len(data)
    offset = 0

    def layer(name, start, finish, **fields):
        p.layers.append(Layer(name, start, finish, fields))
        p.protocols.add(name)

    def u16(at):
        return struct.unpack_from("!H", data, at)[0]

    try:
        if frame.link == 1:
            require(end >= 14, "以太网头截断")
            p.dst, p.src = mac(data[:6]), mac(data[6:12])
            kind = u16(12)
            layer("Ethernet", 0, 14, 源=p.src, 目的=p.dst, EtherType=hex(kind))
            offset = 14
            while kind in (0x8100, 0x88a8):
                require(offset + 4 <= end, "VLAN 标签截断")
                tag, kind = struct.unpack_from("!HH", data, offset)
                layer("VLAN", offset, offset + 4, ID=tag & 4095, EtherType=hex(kind))
                offset += 4
        elif frame.link in (0, 108):
            require(end >= 4, "回环头截断")
            family = int.from_bytes(data[:4], "little" if frame.link == 0 else "big")
            layer("Loopback", 0, 4, 地址族=family)
            kind = 0x800 if family == 2 else 0x86dd if family in (10, 23, 24, 28, 30) else 0
            offset = 4
        elif frame.link in (12, 101, 228, 229):
            require(end > 0, "IP 数据为空")
            kind = {4: 0x800, 6: 0x86dd}.get(data[0] >> 4, 0)
        else:
            raise ValueError(f"未支持链路类型 {frame.link}")

        if kind == 0x806:
            require(offset + 8 <= end, "ARP 头截断")
            hw, proto, hlen, plen, operation = struct.unpack_from("!HHBBH", data, offset)
            size = 8 + 2 * (hlen + plen)
            require(offset + size <= end, "ARP 地址截断")
            fields = {"操作": operation, "硬件类型": hw, "协议类型": hex(proto)}
            if (hw, proto, hlen, plen) == (1, 0x800, 6, 4):
                a = offset + 8
                p.src, p.dst = map(str, (ip_address(data[a+6:a+10]), ip_address(data[a+16:a+20])))
                fields.update(源IP=p.src, 目的IP=p.dst, 源MAC=mac(data[a:a+6]), 目的MAC=mac(data[a+10:a+16]))
            layer("ARP", offset, offset + size, **fields)
            return p

        if kind == 0x800:
            require(offset + 20 <= end and data[offset] >> 4 == 4, "IPv4 头截断或版本错误")
            size = (data[offset] & 15) * 4
            total = u16(offset + 2)
            require(20 <= size <= total and offset + size <= end, "IPv4 头长度非法")
            fragment = u16(offset + 6)
            number = data[offset+9]
            p.src = str(ip_address(data[offset+12:offset+16]))
            p.dst = str(ip_address(data[offset+16:offset+20]))
            layer("IPv4", offset, offset + size, 源=p.src, 目的=p.dst, TTL=data[offset+8],
                  协议号=number, 总长度=total, 分片偏移=(fragment & 8191)*8, 更多分片=bool(fragment & 8192))
            if fragment & 0x3fff:
                p.summary = "IPv4 分片，未重组"
                return p
            if offset + total > end:
                p.error = "IPv4 负载截断"
            end = min(end, offset + total)
            offset += size
        elif kind == 0x86dd:
            require(offset + 40 <= end and data[offset] >> 4 == 6, "IPv6 头截断或版本错误")
            size, number, hops = struct.unpack_from("!HBB", data, offset + 4)
            p.src = str(ip_address(data[offset+8:offset+24]))
            p.dst = str(ip_address(data[offset+24:offset+40]))
            layer("IPv6", offset, offset + 40, 源=p.src, 目的=p.dst, 跳数限制=hops,
                  下一头部=number, 负载长度=size)
            if offset + 40 + size > end:
                p.error = "IPv6 负载截断"
            end = min(end, offset + 40 + size)
            offset += 40
            for _ in range(32):
                if number not in (0, 43, 44, 51, 60):
                    break
                require(offset + 2 <= end, "IPv6 扩展头截断")
                nxt, length = data[offset:offset+2]
                size = 8 if number == 44 else (length + 2)*4 if number == 51 else (length + 1)*8
                require(offset + size <= end, "IPv6 扩展头长度非法")
                layer("IPv6 扩展头", offset, offset+size, 类型=number, 下一头部=nxt)
                if number == 44 and u16(offset+2) & 0xfff9:
                    p.summary = "IPv6 分片，未重组"
                    return p
                number, offset = nxt, offset + size
            else:
                raise ValueError("IPv6 扩展头过多")
        else:
            p.summary = f"EtherType {kind:#06x}"
            return p

        if number == 6:
            require(offset + 20 <= end, "TCP 头截断")
            sport, dport, seq, ack, ctrl, window = struct.unpack_from("!HHIIHH", data, offset)
            size = (ctrl >> 12) * 4
            require(20 <= size <= end-offset, "TCP 头长度非法")
            p.sport, p.dport, p.seq, p.ack, p.flags = sport, dport, seq, ack, ctrl & 0x1ff
            p.payload_offset = offset + size
            p.payload_length = end - p.payload_offset
            flags = " ".join(name for bit, name in enumerate(
                ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")) if p.flags & (1 << bit))
            layer("TCP", offset, offset + size, 源端口=sport, 目的端口=dport,
                  Seq=seq, Ack=ack, Flags=flags, 窗口=window, 可见负载长度=p.payload_length)
            p.summary = f"{sport} → {dport} [{flags}] Seq={seq} Ack={ack}"
            offset += size
        elif number == 17:
            require(offset + 8 <= end, "UDP 头截断")
            sport, dport, size = struct.unpack_from("!HHH", data, offset)
            require(size >= 8, "UDP 长度非法")
            p.sport, p.dport = sport, dport
            layer("UDP", offset, offset + 8, 源端口=sport, 目的端口=dport, 长度=size)
            p.summary = f"{sport} → {dport}"
            if offset + size > end:
                p.error = "UDP 负载截断"
            end = min(end, offset + size)
            offset += 8
            p.payload_length = end - offset
        elif number in (1, 58):
            require(offset + 4 <= end, "ICMP 头截断")
            typ, code, checksum = struct.unpack_from("!BBH", data, offset)
            name = "ICMP" if number == 1 else "ICMPv6"
            layer(name, offset, offset + 4, 类型=typ, 代码=code, 校验和=hex(checksum))
            p.summary = f"Type={typ} Code={code}"
            is_unreachable = (number == 1 and typ == 3) or (number == 58 and typ == 1)
            if is_unreachable and offset + 8 < end:
                quoted = data[offset+8:end]
                if quoted[0] >> 4 in (4, 6):
                    # Use only the quoted IP/transport header. ICMP may embed another ICMP.
                    v4 = quoted[0] >> 4 == 4
                    ip_size = (quoted[0] & 15)*4 if v4 else 40
                    at = 9 if v4 else 6
                    if len(quoted) >= ip_size + 4 and ip_size >= 20 and quoted[at] in (6,17):
                        src = str(ip_address(quoted[12:16] if v4 else quoted[8:24]))
                        dst = str(ip_address(quoted[16:20] if v4 else quoted[24:40]))
                        ports = struct.unpack_from("!HH", quoted, ip_size)
                        p.summary += f" · 引用 {src}:{ports[0]} → {dst}:{ports[1]}"
                        p.layers[-1].fields["原始端点"] = p.summary
            return p
        else:
            p.summary = f"IP 协议号 {number}"
            return p

        if 53 in (p.sport, p.dport):
            if number == 6:
                if end - offset < 2:
                    return p
                length = u16(offset)
                if end - offset - 2 < length:
                    return p
                offset += 2
                end = offset + length
            dns(data, offset, end, p, layer)
        elif number == 6 and end > offset:
            http(data, offset, end, p, layer)
            if "HTTP" not in p.protocols:
                fields = tls(data[offset:end])
                if fields:
                    layer("TLS", offset, min(end, offset + 5 + fields["记录长度"]), **fields)
                    p.summary = fields.get("可见握手类型", fields["记录类型"])
        elif number == 17 and end > offset:
            fields = quic(data[offset:end])
            if fields:
                layer("QUIC", offset, end, **fields)
                p.summary = f'{fields["长报文类型"]} · 加密传输'
    except (ValueError, struct.error) as exc:
        p.error = f"{p.error}；{exc}" if p.error else str(exc)
    return p


HTTP_LINE = re.compile(rb"(?:[!#$%&'*+.^_~0-9A-Za-z-]{1,32} [^ \r\n]+ HTTP/1\.[01]|HTTP/1\.[01] [0-9]{3}(?: [^\r\n]*)?)")


def http(data, offset, end, packet, layer):
    visible = data[offset:min(end, offset + 8192)]
    line, separator, _ = visible.partition(b"\r\n")
    if not separator or not HTTP_LINE.fullmatch(line):
        return
    summary = line.decode("ascii", "replace")
    marker = visible.find(b"\r\n\r\n")
    finish = marker + 4 if marker >= 0 else len(line) + 2
    headers = {"首行": summary}
    if marker >= 0:
        headers["报头"] = visible[len(line)+2:marker].decode("iso-8859-1", "replace")
    layer("HTTP", offset, offset + finish, **headers)
    packet.summary = summary


def dns(data, offset, end, packet, layer):
    if end == offset:
        return
    require(end - offset >= 12, "DNS 头截断")
    txid, flags, questions, answers, auth, extra = struct.unpack_from("!6H", data, offset)
    fields = dict(ID=hex(txid), 类型="响应" if flags & 0x8000 else "查询",
                  查询数=questions, 回答数=answers, 授权数=auth, 附加数=extra, RCODE=flags & 15)
    def read_name(position):
        following = None
        visited, labels = set(), []
        while True:
            require(position < end and position not in visited and len(visited) < 128,
                    "DNS 名称截断或压缩指针循环")
            visited.add(position)
            length = data[position]
            if length == 0:
                break
            if length & 0xc0 == 0xc0:
                require(position+1 < end, "DNS 压缩指针截断")
                if following is None:
                    following = position + 2
                position = offset + (((length & 63) << 8) | data[position+1])
            else:
                require(length <= 63 and position + 1 + length <= end, "DNS 标签非法")
                labels.append(data[position+1:position+1+length].decode("ascii", "replace"))
                position += length + 1
        return ".".join(labels) or ".", following if following is not None else position + 1

    position = offset + 12
    for index in range(questions):
        name, position = read_name(position)
        require(position + 4 <= end, "DNS 查询字段截断")
        if index == 0:
            fields["查询名"] = name
            fields["查询类型"] = struct.unpack_from("!H", data, position)[0]
        position += 4
    records = []
    for _ in range(min(answers, 16)):
        name, position = read_name(position)
        require(position + 10 <= end, "DNS 回答头截断")
        kind, _, ttl, length = struct.unpack_from("!HHIH", data, position)
        position += 10
        require(position + length <= end, "DNS 回答截断")
        if (kind, length) in ((1, 4), (28, 16)):
            value = str(ip_address(data[position:position+length]))
        elif kind == 5:
            value, consumed = read_name(position)
            require(consumed <= position + length, "DNS CNAME 长度错误")
        else:
            value = f"类型 {kind} · {length} B"
        records.append(f"{name} → {value} · TTL {ttl}")
        position += length
    if records:
        fields["回答"] = " | ".join(records)
    layer("DNS", offset, end, **fields)
    packet.summary = f'{fields["类型"]} {fields.get("查询名", "")}'.strip()

