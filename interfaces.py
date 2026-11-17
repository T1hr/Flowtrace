"""Windows interface aliases and local addresses for Npcap and UDP matching."""
import ctypes as C
from ipaddress import ip_address
from uuid import UUID


class Unicast(C.Structure):
    pass


Unicast._fields_ = [("alignment", C.c_uint64), ("next", C.POINTER(Unicast)),
                    ("address", C.c_void_p), ("length", C.c_int)]


class Adapter(C.Structure):
    pass


Adapter._fields_ = [
    ("alignment", C.c_uint64), ("next", C.POINTER(Adapter)), ("name", C.c_char_p),
    ("unicast", C.POINTER(Unicast)), ("anycast", C.c_void_p), ("multicast", C.c_void_p),
    ("dns", C.c_void_p), ("suffix", C.c_wchar_p), ("description", C.c_wchar_p),
    ("friendly", C.c_wchar_p), ("hardware", C.c_ubyte * 8), ("hardware_len", C.c_uint32),
    ("flags", C.c_uint32), ("mtu", C.c_uint32), ("kind", C.c_uint32), ("status", C.c_int),
]


def interface_key(value):
    try:
        return UUID(value[value.index("{"):])
    except ValueError:
        return None


def adapters():
    api = C.WinDLL("iphlpapi").GetAdaptersAddresses
    api.argtypes = [C.c_uint32, C.c_uint32, C.c_void_p, C.c_void_p, C.POINTER(C.c_uint32)]
    api.restype = C.c_uint32
    size = C.c_uint32(15000)
    for _ in range(3):
        memory = C.create_string_buffer(size.value)
        code = api(0, 2 | 4 | 8 | 0x100, None, memory, C.byref(size))
        if code == 0:
            break
        if code != 111 or size.value > 16 * 1024**2:
            return {}
    else:
        return {}
    result = {}
    entry = C.cast(memory, C.POINTER(Adapter))
    while entry:
        value = entry.contents
        key = interface_key((value.name or b"").decode("ascii", "replace"))
        addresses = []
        node = value.unicast
        while node:
            item = node.contents
            if item.address and item.length >= 8:
                family = C.c_uint16.from_address(item.address).value
                if family == 2:
                    addresses.append(str(ip_address(C.string_at(item.address + 4, 4))))
                elif family == 23 and item.length >= 24:
                    addresses.append(str(ip_address(C.string_at(item.address + 8, 16))))
            node = item.next
        kinds = {6: "以太网", 23: "点对点", 24: "回环", 71: "WLAN", 131: "隧道"}
        kind = "蓝牙 PAN" if "bluetooth" in (value.description or "").lower() else kinds.get(value.kind, "网络接口")
        if key is not None:
            result[key] = (value.friendly or value.description or "接口", kind, value.status == 1, addresses)
        entry = value.next
    return result


def local_addresses():
    return {"127.0.0.1", "::1"}.union(*(row[3] for row in adapters().values()))

