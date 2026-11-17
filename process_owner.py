"""Sample Windows IPv4/IPv6 TCP and UDP process ownership."""
import ctypes as C
from ipaddress import ip_address
from pathlib import PureWindowsPath
import socket
import struct
import time
from interfaces import local_addresses


class ProcessOwners:
    def __init__(self):
        library = C.WinDLL("iphlpapi")
        self.queries = {"TCP": library.GetExtendedTcpTable, "UDP": library.GetExtendedUdpTable}
        u32 = C.c_uint32
        for query in self.queries.values():
            query.argtypes = [C.c_void_p, C.POINTER(u32), C.c_int, u32, C.c_int, u32]
            query.restype = u32
        self.kernel = C.WinDLL("kernel32")
        self.kernel.OpenProcess.argtypes = [u32, C.c_int, u32]
        self.kernel.OpenProcess.restype = C.c_void_p
        self.kernel.QueryFullProcessImageNameW.argtypes = [C.c_void_p, u32, C.c_wchar_p, C.POINTER(u32)]
        self.kernel.CloseHandle.argtypes = [C.c_void_p]
        self.rows = {}
        self.udp = {}
        self.names = {}
        self.next_sample = 0
        self.local_addresses = local_addresses()
        self.errors = {}

    def table(self, family, protocol):
        key = (family, protocol)
        size = C.c_uint32()
        buffer = None
        for _ in range(3):
            result = self.queries[protocol](buffer, C.byref(size), 0, family, 4 if protocol == "TCP" else 1, 0)
            if result == 0:
                self.errors.pop(key, None)
                return buffer.raw[:size.value] if buffer is not None else b
            if result != 122 or size.value > 32 * 1024**2:
                break
            buffer = C.create_string_buffer(size.value)
        self.errors[key] = result
        return b""

    def sample(self):
        rows = {}
        for family, layout in ((socket.AF_INET, "<I4sI4sII"),
                               (socket.AF_INET6, "<16sII16sIIII")):
            data = self.table(family, "TCP")
            if len(data) < 4:
                continue
            count, = struct.unpack_from("<I", data)
            row = struct.Struct(layout)
            if count * row.size > len(data) - 4:
                continue
            for values in row.iter_unpack(data[4:4 + count * row.size]):
                if family == socket.AF_INET:
                    _, local, lp, remote, rp, pid = values
                else:
                    local, _, lp, remote, _, rp, _, pid = values
                if pid and lp and rp:
                    key = ((str(ip_address(local)), socket.ntohs(lp & 65535)),
                           (str(ip_address(remote)), socket.ntohs(rp & 65535)))
                    rows[key] = pid
        udp = {}
        for family, layout in ((socket.AF_INET, "<4sII"), (socket.AF_INET6, "<16sIII")):
            data = self.table(family, "UDP")
            if len(data) < 4:
                continue
            count, = struct.unpack_from("<I", data)
            row = struct.Struct(layout)
            if count * row.size > len(data) - 4:
                continue
            for address, *_, port, pid in row.iter_unpack(data[4:4 + count * row.size]):
                if pid and port:
                    key = (str(ip_address(address)), socket.ntohs(port & 65535))
                    udp.setdefault(key, set()).add(pid)
        self.udp = udp
        active = set(rows.values()).union(*udp.values())
        self.names = {pid: self.names[pid] for pid in active if pid in self.names}
        self.rows = rows

    def name(self, pid):
        if pid not in self.names:
            name = "进程名不可用"
            handle = self.kernel.OpenProcess(0x1000, 0, pid)
            if handle:
                try:
                    buffer = C.create_unicode_buffer(32768)
                    length = C.c_uint32(len(buffer))
                    if self.kernel.QueryFullProcessImageNameW(handle, 0, buffer, C.byref(length)):
                        name = PureWindowsPath(buffer.value).name
                finally:
                    self.kernel.CloseHandle(handle)
            self.names[pid] = name
        return self.names[pid]

    def lookup(self, packet):
        now = time.monotonic()
        if now >= self.next_sample:
            self.sample()
            self.next_sample = now + 0.2
        src = (packet.src, packet.sport)
        dst = (packet.dst, packet.dport)
        if "TCP" in packet.protocols:
            pids = self.rows.get((src, dst)), self.rows.get((dst, src))
        else:
            pids = (self.udp_owner(src), self.udp_owner(dst))
        return tuple((pid, self.name(pid)) if pid else None for pid in pids)

    def udp_owner(self, endpoint):
        address, port = endpoint
        candidates = self.udp.get(endpoint)
        if candidates is None and address in self.local_addresses:
            candidates = self.udp.get(("::" if ":" in address else "0.0.0.0", port))
        return next(iter(candidates)) if candidates and len(candidates) == 1 else None

