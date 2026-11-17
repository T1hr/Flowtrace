"""Capture handoff, analysis and temporary PCAP recording."""
from pathlib import Path
from queue import Empty, Full, Queue
from tempfile import NamedTemporaryFile, TemporaryFile
from threading import Event, Lock, Thread

from capture_file import read_pcap, write_frame, write_pcap_header
from decode import decode
from process_owner import ProcessOwners


class Session:
    def __init__(self, source, recording=None):
        self.input = Queue(maxsize=1024)
        self.results = Queue(maxsize=512)
        self.stop = Event()
        self.source_done = Event()
        self.done = Event()
        self.dropped = 0
        self.driver_dropped = None
        self.error = ""
        self.write_error = ""
        self.owner_warning = ""
        self.link = None
        self.recording = recording if recording is not None else Recording()
        self.received = 0
        self.source = source
        self.live = not isinstance(source, Path)
        self.reader = Thread(target=self._read, name="Capture")
        self.analyzer = Thread(target=self._analyze, name="Analysis")

    def start(self):
        self.analyzer.start()
        self.reader.start()

    def ready(self, link):
        if self.live and self.recording.link not in (None, link):
            raise RuntimeError('继续捕获时链路类型发生变化，请新建捕获。')
        self.link = link

    def _read(self):
        def submit(frame):
            self.received += 1
            try:
                self.input.put_nowait(frame)
            except Full:
                self.dropped += 1

        try:
            if self.live:
                self.driver_dropped = self.source(self.stop, submit, self.ready)
            else:
                with self.source.open("rb") as stream:
                    for frame in read_pcap(stream, self.ready):
                        while not self.stop.is_set():
                            try:
                                self.input.put(frame, timeout=0.05)
                                break
                            except Full:
                                continue
                        if self.stop.is_set():
                            break
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.source_done.set()

    def _analyze(self):
        try:
            owners = ProcessOwners() if self.live else None
            while True:
                try:
                    frame = self.input.get(timeout=0.05)
                except Empty:
                    if self.source_done.is_set() and self.input.empty():
                        break
                    continue
                if self.live and not self.write_error:
                    self._record(frame)
                packet = decode(frame)
                if owners and packet.sport is not None and ("TCP" in packet.protocols or "UDP" in packet.protocols):
                    packet.owners = owners.lookup(packet)
                    self.owner_warning = ("Windows TCP/UDP 端点表部分或全部不可用"
                                          if owners.errors else "")
                self.results.put(packet)
        except Exception as exc:
            self.error = f"分析失败：{exc}"
            self.stop.set()
        finally:
            self.source_done.wait()
            self.reader.join()
            self.done.set()

    def _record(self, frame):
        try:
            self.recording.append(frame)
        except OSError as exc:
            self.write_error = str(exc)

    def save(self, target):
        self.recording.save(target, self.recording.size)

    def discard(self):
        self.recording.close()


class Recording:
    """One append-only PCAP spool shared by capture runs with equal settings."""

    def __init__(self):
        self.lock = Lock()
        self.stream = None
        self.link = None
        self.size = 0
        self.saved_size = 0
        self.frames = 0

    @property
    def dirty(self):
        return self.size != self.saved_size

    def append(self, frame):
        with self.lock:
            if self.stream is None:
                self.stream = TemporaryFile(mode="w+b")
                write_pcap_header(self.stream, frame.link)
                self.link = frame.link
                self.size = self.stream.tell()
            self.stream.seek(self.size)
            write_frame(self.stream, frame)
            self.size = self.stream.tell()
            self.frames += 1

    def save(self, target, length):
        if not length:
            raise ValueError("当前会话没有可保存的 PCAP")
        partial = None
        try:
            with NamedTemporaryFile(dir=target.parent, suffix=".part", delete=False) as output:
                partial = Path(output.name)
                offset = 0
                while offset < length:
                    with self.lock:
                        self.stream.seek(offset)
                        data = self.stream.read(min(length - offset, 1024**2))
                    if not data:
                        raise OSError("捕获暂存数据不完整")
                    output.write(data)
                    offset += len(data)
            partial.replace(target)
            self.saved_size = length
        finally:
            if partial is not None:
                partial.unlink(missing_ok=True)

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None
