"""TCP sequence normalization and byte-preserving stream presentation."""

STREAM_BUDGET = 32 * 1024**2
SEGMENT_LIMIT = 100000
DISPLAY_BYTES = 512 * 1024


def relative(seq, origin):
    return ((seq - origin + 2**31) % 2**32) - 2**31


def reassemble(segments, origin=None):
    """Yield contiguous byte runs and explicit gaps. Sort in TCP sequence order."""
    if not segments:
        return
    anchored = origin is not None
    if origin is None:
        origin = segments[0][0]
    ordered = sorted(((relative(seq, origin), raw) for seq, raw in segments),
                     key=lambda item: item[0])
    cursor = min(0, ordered[0][0]) if anchored else ordered[0][0]
    pending = bytearray()
    for position, raw in ordered:
        if position > cursor:
            if pending:
                yield bytes(pending)
                pending.clear()
            yield position - cursor
            cursor = position
        unseen = raw[cursor - position:]
        if unseen:
            pending.extend(unseen)
            cursor += len(unseen)
    if pending:
        yield bytes(pending)


def readable(data, hex_mode):
    if hex_mode:
        return "\n".join(data[i:i+16].hex(" ") for i in range(0, len(data), 16))
    text = data.decode("utf-8", "backslashreplace").replace("\r\n", "\n")
    return "".join(char if char in "\n\t" or char.isprintable()
                   else f"\\x{ord(char):02x}" for char in text)

