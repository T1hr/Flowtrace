"""Generate safe demo data and verify offline parsing or local-only Npcap capture."""
from collections import Counter
from io import BytesIO
from pathlib import Path
import socket
import struct
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
import unittest

from analysis_core import FlowTracker, display_filter
from capture_file import Frame, read_pcap, write_frame, write_pcap_header
from decode import decode
from npcap import Npcap
from session import Session
from tcp_stream import reassemble


DEMO = Path(__file__).with_name("demo.pcap")


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(data)//2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def fixtures(diagnostic=False):
    a, b = map(socket.inet_aton, ("192.0.2.10", "192.0.2.20"))
    eth = bytes.fromhex("0200000000200200000000100800")
    packets = []

    def add(payload, protocol, reverse=False):
        src, dst = (b, a) if reverse else (a, b)
        if protocol in (6, 17):
            offset = 16 if protocol == 6 else 6
            pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(payload))
            value = checksum(pseudo + payload)
            payload = payload[:offset] + struct.pack("!H", value or 65535) + payload[offset+2:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(payload),
                         len(packets), 0, 64, protocol, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        header = eth[6:12] + eth[:6] + eth[12:] if reverse else eth
        packets.append(header + ip + payload)

    def tcp(flags, seq, ack, body=b"", reverse=False, client=49000):
        ports = (80, client) if reverse else (client, 80)
        add(struct.pack("!HHIIHHHH", *ports, seq, ack, 0x5000 | flags, 8192, 0, 0) + body, 6, reverse)

    req = b"GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    tcp(2, 100, 0)
    tcp(18, 200, 101, reverse=True)
    tcp(16, 101, 201)
    tcp(24, 101, 201, req)
    # Response body arrives out of sequence, then its prefix and a retransmission.
    split = len(resp) - 2
    tcp(24, 201+split, 101+len(req), resp[split:], True)
    tcp(24, 201, 101+len(req), resp[:split], True)
    tcp(24, 201+split, 101+len(req), resp[split:], True)
    tcp(17, 101+len(req), 201+len(resp))
    tcp(17, 201+len(resp), 102+len(req), reverse=True)
    tcp(16, 102+len(req), 202+len(resp))
    dns = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0) + b"\x07example\x04test\0\0\x01\0\x01"
    add(struct.pack("!4H", 49500, 53, len(dns)+8, 0) + dns, 17)
    icmp = b"\x08\0\0\0\0\x01\0\x01demo"
    add(icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:], 1)
    src6 = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
    dst6 = socket.inet_pton(socket.AF_INET6, "2001:db8::20")
    echo = b"\x80\0\0\0\0\x01\0\x01demo"
    pseudo = src6 + dst6 + struct.pack("!I3xB", len(echo), 58)
    echo = echo[:2] + struct.pack("!H", checksum(pseudo + echo)) + echo[4:]
    packets.append(eth[:12] + b"\x86\xdd" +
                   struct.pack("!IHBB16s16s", 6 << 28, len(echo), 58, 64, src6, dst6) + echo)
    packets.append(eth[:12] + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x800, 6, 4, 1)
                   + eth[6:12] + a + bytes(6) + b)
    if diagnostic:
        tcp(2, 700, 0, client=49001)
        tcp(2, 700, 0, client=49001)
        tcp(2, 700, 0, client=49001)
        tcp(2, 800, 0, client=49002)
        tcp(20, 0, 801, reverse=True, client=49002)
    return [Frame(1794300000000000000+i*500000000+123, 1, len(raw), raw)
            for i, raw in enumerate(packets)]


def demo():
    with DEMO.open("wb") as stream:
        write_pcap_header(stream, 1)
        for frame in fixtures(diagnostic=True):
            write_frame(stream, frame)


class OfflineTests(unittest.TestCase):
    def test_demo_file_and_protocols(self):
        with DEMO.open("rb") as stream:
            self.assertEqual(list(read_pcap(stream)), fixtures(diagnostic=True))
        packets = [decode(frame) for frame in fixtures()]
        self.assertFalse(any(packet.error for packet in packets))
        counts = Counter(p.protocol for p in packets)
        self.assertEqual(counts, {"TCP": 8, "HTTP": 2, "DNS": 1, "ICMP": 1, "ICMPv6": 1, "ARP": 1})
        self.assertEqual(sum(map(display_filter("http or (ipv6 and icmp)"), packets)), 3)
        self.assertEqual(sum(map(display_filter("udp and ipv4 and not http"), packets)), 1)
        with self.assertRaises(ValueError):
            display_filter("(http or )")

    def test_bidirectional_flow_and_reuse(self):
        tracker = FlowTracker()
        self.assertEqual([tracker.update(decode(f)) for f in fixtures()[:10]], [1]*10)
        flow = tracker.flows[1]
        self.assertEqual(flow.packets, [5, 5])
        self.assertEqual(flow.state, "已双向 FIN")
        next_frame = fixtures()[0]
        self.assertEqual(tracker.update(decode(Frame(flow.end+1, 1, next_frame.wire, next_frame.raw))), 2)

    def test_reassembly(self):
        tracker = FlowTracker()
        for frame in fixtures():
            tracker.update(decode(frame))
        flow = tracker.flows[1]
        response, = reassemble(flow.segments[1], flow.origins[1])
        self.assertEqual(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        self.assertEqual(list(reassemble([(2, b"EF"), (0xfffffffe, b"AB")], 0xfffffffe)),
                         [b"AB", 2, b"EF"])
        self.assertEqual(list(reassemble([(5, b"abc"), (6, b"bcd"), (5, b"abc")], 5)),
                         [b"abcd"])

    def test_truncation_and_raw_preservation(self):
        for frame in fixtures():
            for i in range(len(frame.raw)):
                raw = frame.raw[:i]
                packet = decode(Frame(frame.ns, frame.link, frame.wire, raw))
                self.assertEqual(packet.frame.raw, raw)
        data = DEMO.read_bytes()
        with self.assertRaises(ValueError):
            list(read_pcap(BytesIO(data[:-1])))

    def test_big_endian_pcap(self):
        frame = fixtures()[0]
        raw = frame.raw
        blob = struct.pack(">IHHIIIIIIII", 0xa1b2c3d4, 2, 4, 0, 0, 4096, 1, 123, 456, len(raw), len(raw))
        self.assertEqual(list(read_pcap(BytesIO(blob+raw))), [Frame(123000456000, 1, len(raw), raw)])

    def test_offline_session(self):
        session = Session(DEMO)
        session.start()
        self.assertTrue(session.done.wait(5))
        self.assertFalse(session.error)
        packets = [session.results.get_nowait() for _ in fixtures(diagnostic=True)]
        self.assertEqual([packet.frame for packet in packets], fixtures(diagnostic=True))


def live():
    backend = Npcap()
    device = next(item for item in backend.interfaces() if item.loopback)
    with TemporaryDirectory(dir=Path.cwd()) as scratch, socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(4)
        port = server.getsockname()[1]
        invalid_stop = Event()
        invalid_stop.set()
        try:
            backend.capture(device, "tcp and (", invalid_stop, lambda f: None, lambda l: None)
        except RuntimeError as exc:
            if "BPF" not in str(exc):
                raise SystemExit(f"实时捕获无法启动：{exc}") from exc
            print("非法 BPF 已拒绝")
        else:
            raise AssertionError("非法 BPF 被接受")

        output = Path(scratch) / "loopback.pcap"
        session = Session(lambda stop, submit, ready: backend.capture(
            device, f"host 127.0.0.1 and tcp port {port}", stop, submit, ready))
        session.start()
        try:
            for _ in range(200):
                if session.link is not None or session.done.wait(0.02):
                    break
            assert session.link is not None, session.error
            def serve():
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(3)
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            thread = Thread(target=serve)
            thread.start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    assert b"200 OK" in client.makefile("rb").read()
            finally:
                thread.join(5)
            import time
            time.sleep(0.35)
        finally:
            session.stop.set()
            assert session.done.wait(5), "抓包线程停止超时"
        assert not session.error and not session.write_error, (session.error, session.write_error)
        packets = [session.results.get_nowait() for _ in range(session.results.qsize())]
        session.save(output)
        session.discard()
        with output.open("rb") as stream:
            assert list(read_pcap(stream)) == [p.frame for p in packets]
        assert all(port in (p.sport, p.dport) for p in packets)
        assert sum("HTTP" in p.protocols for p in packets) >= 2
        tracker = FlowTracker()
        for packet in packets:
            tracker.update(packet)
        flow, = tracker.flows.values()
        assert min(flow.packets) > 0
        import os
        assert all(any(pid == os.getpid() for pid, _ in owners) for owners in flow.owners)
        print(f"实时验证通过：链路类型 {session.link}，{len(packets)} 包，方向计数 {flow.packets}，"
              f"队列丢弃 {session.dropped}，后端丢包 {session.driver_dropped}，PCAP 逐帧一致")


if __name__ == "__main__":
    if sys.argv[1:] == ["--generate-demo"]:
        demo()
    elif sys.argv[1:] == ["--live"]:
        live()
    else:
        unittest.main()

