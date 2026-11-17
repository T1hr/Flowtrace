"""Capture observations for process, conversation and packet sequence views."""
from collections import Counter, deque
from dataclasses import dataclass, field

from analysis_core import endpoint


def transport(packet):
    if "TCP" in packet.protocols:
        return "TCP"
    if "UDP" in packet.protocols:
        return "UDP"
    return packet.protocol


@dataclass
class Traffic:
    sent: int = 0
    received: int = 0
    octets: int = 0
    protocols: Counter = field(default_factory=Counter)
    conversations: set = field(default_factory=set)

    @property
    def packets(self):
        return self.sent + self.received

    def observe(self, packet, direction, key):
        self.sent += direction == 0
        self.received += direction == 1
        self.octets += packet.frame.wire
        self.protocols[packet.protocol] += 1
        if key is not None:
            self.conversations.add(key)


@dataclass
class Event:
    number: int
    ns: int
    side: int
    label: str
    severity: str


class Conversation:
    def __init__(self, key):
        self.protocol, self.a, self.b, self.generation = key
        self.first = []
        self.latest = deque(maxlen=90)
        self.count = 0
        self.octets = 0
        self.owners = set()
        self.syn = None
        self.reply = None
        self.established = False
        self.reset = False
        self.fin = set()
        self.retries = 0
        self.data = [set(), set()]
        self.start = None
        self.end = None
        self.gaps = 0
        self.events_seen = 0

    def update(self, number, packet, paused=False):
        src = (packet.src, packet.sport)
        side = int(src != self.a)
        now = packet.frame.ns
        self.count += 1
        self.octets += packet.frame.wire
        if self.start is None:
            self.start = now
        self.end = now
        self.owners.update(owner for owner in packet.owners if owner)
        if paused:
            self.mark(Event(number, now, side, "恢复捕获 · 中间区间未采集", "warn"))
        flags = packet.flags
        severity = "normal"
        detail = packet.summary or packet.protocol
        if self.protocol == "TCP":
            if flags & 4:
                self.reset = True
                severity, detail = "error", "RST · 连接复位"
            elif flags & 0x12 == 2:
                if self.syn and self.syn[:2] == (side, packet.seq):
                    self.retries += 1
                    severity, detail = "warn", "SYN · 同一序号再次发送"
                elif self.syn is None:
                    self.syn = side, packet.seq, now
                    detail = "SYN · 发起连接"
            elif flags & 0x12 == 0x12 and self.syn and side != self.syn[0] and packet.ack == (self.syn[1] + 1) % 2**32:
                if self.reply is None:
                    self.reply = packet.seq, now
                detail = f"SYN/ACK · 回应 {max(0, (now-self.syn[2])/1e6):.2f} ms"
            elif (self.reply and not self.established and side == self.syn[0] and flags & 0x10
                  and packet.ack == (self.reply[0] + 1) % 2**32):
                self.established = True
                detail = f"ACK · 握手完成 · {detail}"
            if flags & 1 and not flags & 4:
                self.fin.add(side)
                detail = "FIN · 请求关闭"
            if packet.payload_length:
                signature = (packet.seq, packet.payload_length)
                if signature in self.data[side] and severity == "normal":
                    severity, detail = "warn", f"可能重传 · {detail}"
                if len(self.data[side]) < 4096:
                    self.data[side].add(signature)
                detail += f" · 负载 {packet.payload_length} B"
        elif packet.payload_length:
            detail += f" · 数据报负载 {packet.payload_length} B"
        self.mark(Event(number, now, side, detail, severity))

    def mark(self, event):
        self.events_seen += 1
        if len(self.first) < 36:
            self.first.append(event)
        else:
            self.latest.append(event)

    @property
    def state(self):
        if self.reset:
            return "观察到 RST"
        if len(self.fin) == 2:
            return "双向 FIN"
        if self.fin:
            return "单向 FIN"
        if self.established:
            return "握手完成"
        if self.reply:
            return "已见 SYN/ACK"
        if self.syn:
            return f"未见 SYN/ACK · {self.retries} 次重发"
        return "UDP 会话" if self.protocol == "UDP" else "未见起始握手"

    @property
    def label(self):
        return f"{endpoint(*self.a)} ↔ {endpoint(*self.b)}"


class Diagnostics:
    def __init__(self):
        self.processes = {}
        self.conversations = {}
        self.unknown = 0
        self.eligible = 0
        self.truncated = 0
        self.unparsed = 0
        self.errors = 0
        self.link_types = Counter()

    def accept(self, number, packet, flow, paused_keys):
        self.truncated += len(packet.frame.raw) < packet.frame.wire
        self.unparsed += not packet.layers
        self.errors += bool(packet.error)
        self.link_types[packet.frame.link] += 1
        protocol = transport(packet)
        if protocol not in ("TCP", "UDP"):
            return
        self.eligible += 1
        if not any(packet.owners):
            self.unknown += 1
        a, b = sorted(((packet.src, packet.sport), (packet.dst, packet.dport)))
        key = protocol, a, b, flow
        if key not in self.conversations:
            self.conversations[key] = Conversation(key)
        conversation = self.conversations[key]
        paused = key in paused_keys
        if paused:
            paused_keys.discard(key)
            conversation.gaps += 1
        conversation.update(number, packet, paused)
        for side, owner in enumerate(packet.owners):
            if owner:
                self.processes.setdefault(owner, Traffic()).observe(packet, side, key)

