"""Read-only Windows Npcap binding. Each live handle belongs to one thread."""
import ctypes as C
import os
from pathlib import Path
from dataclasses import dataclass
from capture_file import Frame
from interfaces import adapters, interface_key


class Device(C.Structure):
    pass


Device._fields_ = [
    ("next", C.POINTER(Device)), ("name", C.c_char_p),
    ("description", C.c_char_p), ("addresses", C.c_void_p), ("flags", C.c_uint),
]


class Header(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in ("sec", "usec", "captured", "wire")]


class Filter(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


class Counters(C.Structure):
    _fields_ = [(name, C.c_uint) for name in ("recv", "drop", "ifdrop", "capt")]


@dataclass(frozen=True)
class Interface:
    name: bytes
    label: str
    loopback: bool


def message(data):
    return (data or b"").decode("mbcs", errors="replace")


class Npcap:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("实时抓包需要 Windows 和 Npcap")
        system = Path(os.environ["SystemRoot"]) / "System32"
        path = system / "Npcap" / "wpcap.dll"
        if not path.is_file():
            path = system / "wpcap.dll"
        try:
            with os.add_dll_directory(str(path.parent)):
                self.api = C.CDLL(str(path))
        except OSError as exc:
            raise RuntimeError("无法加载 Npcap。请检查安装及 Python 位数。") from exc
        ptr, string, integer = C.c_void_p, C.c_char_p, C.c_int
        signatures = {
            "findalldevs": (integer, C.POINTER(C.POINTER(Device)), string),
            "freealldevs": (None, C.POINTER(Device)),
            "open_live": (ptr, string, integer, integer, integer, string),
            "setnonblock": (integer, ptr, integer, string),
            "setmintocopy": (integer, ptr, integer),
            "datalink": (integer, ptr),
            "compile": (integer, ptr, C.POINTER(Filter), string, integer, C.c_uint32),
            "setfilter": (integer, ptr, C.POINTER(Filter)),
            "freecode": (None, C.POINTER(Filter)),
            "next_ex": (integer, ptr, C.POINTER(C.POINTER(Header)), C.POINTER(ptr)),
            "stats": (integer, ptr, C.POINTER(Counters)),
            "geterr": (string, ptr),
            "close": (None, ptr),
        }
        for name, (result, *args) in signatures.items():
            function = getattr(self.api, "pcap_" + name)
            function.restype, function.argtypes = result, args

    def interfaces(self):
        head = C.POINTER(Device)()
        error = C.create_string_buffer(256)
        if self.api.pcap_findalldevs(C.byref(head), error):
            raise RuntimeError(message(error.value))
        devices = []
        aliases = adapters()
        try:
            current = head
            while current:
                device = current.contents
                name = message(device.name)
                description = message(device.description)
                label = f"{description}  [{name}]" if description else name
                info = aliases.get(interface_key(name))
                if info:
                    friendly, kind, up, addresses = info
                    address = " / ".join(addresses[:2])
                    label = f"{friendly} · {kind} · {'在线' if up else '未连接'}"
                    if address:
                        label += f" · {address}"
                elif device.flags & 1:
                    label = "本机回环 · Loopback"
                devices.append(Interface(device.name, label, bool(device.flags & 1)))
                current = device.next
        finally:
            self.api.pcap_freealldevs(head)
        return devices

    def capture(self, interface, expression, stop, submit, ready):
        api = self.api
        error = C.create_string_buffer(256)
        handle = api.pcap_open_live(interface.name, 262144, 0, 50, error)
        if not handle:
            raise RuntimeError(message(error.value))

        def check(result, context):
            if result != 0:
                raise RuntimeError(f"{context}：{message(api.pcap_geterr(handle))}")

        try:
            if expression:
                program = Filter()
                check(api.pcap_compile(handle, C.byref(program), expression.encode("ascii"),
                                       1, 0xffffffff), "BPF 编译失败")
                try:
                    check(api.pcap_setfilter(handle, C.byref(program)), "BPF 设置失败")
                finally:
                    api.pcap_freecode(C.byref(program))
            if api.pcap_setnonblock(handle, 1, error):
                raise RuntimeError(message(error.value))
            check(api.pcap_setmintocopy(handle, 1), "Npcap 设置失败")
            link = api.pcap_datalink(handle)
            if link < 0:
                raise RuntimeError("无法读取链路类型")
            ready(link)
            header = C.POINTER(Header)()
            data = C.c_void_p()
            while not stop.is_set():
                status = api.pcap_next_ex(handle, C.byref(header), C.byref(data))
                if status == 0:
                    stop.wait(0.01)
                    continue
                if status != 1:
                    raise RuntimeError(message(api.pcap_geterr(handle)))
                h = header.contents
                submit(Frame(h.sec * 10**9 + h.usec * 1000, link,
                             h.wire, C.string_at(data, h.captured)))
            stats = Counters()
            return stats.drop if api.pcap_stats(handle, C.byref(stats)) == 0 else None
        finally:
            api.pcap_close(handle)

