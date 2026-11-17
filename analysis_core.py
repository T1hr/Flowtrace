"""Display filtering and bidirectional TCP session accounting."""
from dataclasses import dataclass, field
import re
from tcp_stream import SEGMENT_LIMIT, STREAM_BUDGET


PROTOCOLS = {"ethernet", "vlan", "arp", "ipv4", "ipv6", "tcp", "udp", "icmp",
             "icmpv6", "http", "dns", "tls", "quic", "loopback"}


def display_filter(expression):
    tokens = re.findall(r"[a-z0-9_]+|[()]|[^\s]", expression.lower())
    if not tokens:
        return lambda packet: True
    if len(tokens) > 128:
        raise ValueError("表达式过长")
    pos = 0

    def take(token):
        nonlocal pos
        if pos < len(tokens) and tokens[pos] == token:
            pos += 1
            return True
        return False

    def atom():
        nonlocal pos
        if take("not"):
            term = atom()
            return lambda protocols: not term(protocols)
        if take("("):
            term = disjunction()
            if not take(")"):
                raise ValueError(f"第 {pos + 1} 个词项缺少右括号")
            return term
        token = tokens[pos] if pos < len(tokens) else ""
        if token not in PROTOCOLS:
            raise ValueError(f"第 {pos + 1} 个词项需要协议名，遇到 {token or '表达式末尾'}")
        pos += 1
        if token == "icmp":
            return lambda protocols: bool({"icmp", "icmpv6"} & protocols)
        return lambda protocols: token in protocols

    def conjunction():
        terms = [atom()]
        while take("and"):
            terms.append(atom())
        return lambda protocols: all(term(protocols) for term in terms)

    def disjunction():
        terms = [conjunction()]
        while take("or"):
            terms.append(conjunction())
        return lambda protocols: any(term(protocols) for term in terms)

    predicate = disjunction()
    if pos != len(tokens):
        raise ValueError(f"第 {pos + 1} 个词项多余：{tokens[pos]}")
    return lambda packet: predicate({name.lower() for name in packet.protocols})


def endpoint(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


@dataclass
class Flow:
    id: int
    a: tuple
    b: tuple
    start: int
    end: int
    packets: list = field(default_factory=lambda: [0, 0])
    octets: list = field(default_factory=lambda: [0, 0])
    finished: set = field(default_factory=set)
    syn_seq: int | None = None
    state: str = "途中捕获"
    origins: list = field(default_factory=lambda: [None, None])
    segments: tuple = field(default_factory=lambda: ([], []))
    owners: tuple = field(default_factory=lambda: (set(), set()))
    stream_limited: list = field(default_factory=lambda: [False, False])


class FlowTracker:
    def __init__(self, idle_seconds=120):
        self.flows = {}
        self.active = {}
        self.idle = idle_seconds * 10**9
        self.stream_bytes = 0
        self.segment_count = 0

    def update(self, packet):
        if "TCP" not in packet.protocols:
            return None
        src = (packet.src, packet.sport)
        dst = (packet.dst, packet.dport)
        a, b = key = tuple(sorted((src, dst)))
        now = packet.frame.ns
        direction = int(src != a)
        syn = packet.flags & 0x12 == 2
        flow = self.active.get(key)
        if flow is None or now - flow.end > self.idle or (
            syn and (flow.syn_seq != packet.seq or flow.state != "握手中")
        ):
            flow = Flow(len(self.flows) + 1, a, b, now, now,
                        syn_seq=packet.seq if syn else None,
                        state="握手中" if syn else "途中捕获")
            self.flows[flow.id] = self.active[key] = flow
        flow.start, flow.end = min(now, flow.start), max(now, flow.end)
        flow.packets[direction] += 1
        flow.octets[direction] += packet.frame.wire
        for index, owner in enumerate(packet.owners):
            if owner:
                flow.owners[direction ^ index].add(owner)
        sequence = (packet.seq + bool(packet.flags & 2)) % 2**32
        if packet.flags & 2 and flow.origins[direction] is None:
            flow.origins[direction] = sequence
        if packet.payload_length:
            if (self.stream_bytes + packet.payload_length <= STREAM_BUDGET
                    and self.segment_count < SEGMENT_LIMIT and not flow.stream_limited[direction]):
                offset = packet.payload_offset
                flow.segments[direction].append((
                    sequence, packet.frame.raw[offset:offset + packet.payload_length]))
                self.stream_bytes += packet.payload_length
                self.segment_count += 1
            else:
                flow.stream_limited[direction] = True
        if packet.flags & 4:
            flow.state = "已复位"
        elif flow.state != "已复位":
            if packet.flags & 1:
                flow.finished.add(direction)
            if flow.finished:
                flow.state = "已双向 FIN" if len(flow.finished) == 2 else "单向 FIN"
            elif flow.state == "握手中" and packet.flags & 0x12 == 0x10:
                flow.state = "已建立"
        return flow.id

