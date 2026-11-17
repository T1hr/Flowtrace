"""Flowtrace desktop entry point."""
import ctypes
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from queue import Empty, SimpleQueue
from threading import Thread
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from analysis_core import FlowTracker, display_filter, endpoint
from npcap import Npcap
from session import Session
from stream_view import StreamView
from diagnosis import Diagnostics
from diagnosis_view import DiagnosisView


HISTORY_LIMIT = 10000
HISTORY_BYTES = 64 * 1024**2
BASE = Path(__file__).resolve().parent


def table(parent, columns, height):
    box = ttk.Frame(parent)
    tree = ttk.Treeview(box, columns=[key for key, _ in columns], show="headings", height=height, selectmode="browse")
    for key, width in columns:
        tree.heading(key, text=key)
        tree.column(key, width=width, minwidth=55, stretch=key in ("摘要", "端点 A", "端点 B"))
    bar = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(box, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=bar.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    bar.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    box.rowconfigure(0, weight=1)
    box.columnconfigure(0, weight=1)
    return box, tree


class App:
    def __init__(self, root):
        self.root = root
        root.title("Flowtrace · 实验 1A 网络协议分析")
        root.geometry("1240x830")
        root.minsize(940, 660)
        ttk.Style(root).theme_use("clam")
        self.session = None
        self.previous = None
        self.settings = None
        self.saving = False
        self.closing = False
        self.devices = []
        self.interface = tk.StringVar()
        self.bpf = tk.StringVar()
        self.expression = tk.StringVar()
        self.status = tk.StringVar(value="请选择捕获接口，或打开 PCAP 文件。")
        self.metrics = tk.StringVar()
        self.only_flow = None
        self.predicate = display_filter("")
        self.source_label = ""
        self.reset()

        content = ttk.Frame(root, padding=12)
        content.pack(fill="both", expand=True)
        toolbar = ttk.Frame(content)
        toolbar.pack(fill="x", pady=(0, 6))
        ttk.Label(toolbar, text="捕获接口").pack(side="left")
        self.combo = ttk.Combobox(toolbar, state="readonly", textvariable=self.interface, width=38)
        self.combo.pack(side="left", padx=6, fill="x", expand=True)
        self.combo.bind("<<ComboboxSelected>>", lambda event: self.controls())
        self.refresh_button = ttk.Button(toolbar, text="刷新接口", command=self.refresh)
        self.refresh_button.pack(side="left")
        self.start_button = ttk.Button(toolbar, text="开始捕获", command=self.start_live)
        self.start_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(toolbar, text="停止", command=self.stop)
        self.stop_button.pack(side="left")
        self.resume_button = ttk.Button(toolbar, text="继续抓包", command=self.resume)
        self.resume_button.pack(side="left", padx=4)
        self.save_button = ttk.Button(toolbar, text="保存 PCAP", command=self.save_current)
        self.save_button.pack(side="left")
        files = ttk.Frame(content)
        files.pack(fill="x", pady=(0, 6))
        self.open_button = ttk.Button(files, text="打开 PCAP", command=self.open)
        self.open_button.pack(side="left", padx=5)
        self.demo_button = ttk.Button(files, text="诊断示例", command=self.open_demo)
        self.demo_button.pack(side="left")

        filters = ttk.Frame(content)
        filters.pack(fill="x", pady=(0, 7))
        ttk.Label(filters, text="捕获 BPF").pack(side="left")
        self.bpf_input = ttk.Entry(filters, textvariable=self.bpf, width=24)
        self.bpf_input.pack(side="left", padx=5)
        ttk.Label(filters, text="显示过滤").pack(side="left", padx=(15, 0))
        entry = ttk.Entry(filters, textvariable=self.expression)
        entry.pack(side="left", fill="x", expand=True, padx=5)
        entry.bind("<Return>", lambda event: self.apply())
        ttk.Button(filters, text="应用", command=self.apply).pack(side="left")
        ttk.Button(filters, text="清除", command=self.clear).pack(side="left", padx=(5, 0))
        ttk.Label(content, text="显示过滤示例  http or (ipv6 and not udp)    ·    右键 TCP 包或流记录查看原文").pack(anchor="w")

        self.tabs = ttk.Notebook(content)
        self.tabs.pack(fill="both", expand=True, pady=7)
        packets = ttk.Panedwindow(self.tabs, orient="vertical")
        self.tabs.add(packets, text="数据包")
        box, self.packet_table = table(packets, [
            ("序号", 63), ("时间", 153), ("源", 190), ("目的", 190),
            ("协议", 95), ("原始长度", 80), ("摘要", 350)], 14)
        packets.add(box, weight=3)
        self.packet_table.bind("<<TreeviewSelect>>", self.show_packet)
        self.packet_table.bind("<Button-3>", self.packet_menu)

        details = ttk.Panedwindow(packets, orient="horizontal")
        packets.add(details, weight=2)
        tree_box = ttk.Frame(details)
        self.layers = ttk.Treeview(tree_box, show="tree")
        scrollbar = ttk.Scrollbar(tree_box, command=self.layers.yview)
        self.layers.configure(yscrollcommand=scrollbar.set)
        self.layers.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.layers.bind("<<TreeviewSelect>>", self.highlight)
        details.add(tree_box, weight=1)
        hex_box = ttk.Frame(details)
        self.hexview = tk.Text(hex_box, height=12, wrap="none", font=("Consolas", 10),
                               state="disabled", background="#f5f7fa")
        scrollbar = ttk.Scrollbar(hex_box, command=self.hexview.yview)
        self.hexview.configure(yscrollcommand=scrollbar.set)
        self.hexview.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.hexview.tag_configure("layer", background="#ffe6a1")
        details.add(hex_box, weight=3)
        details.bind("<Map>", lambda event: details.after_idle(
            lambda: details.sashpos(0, int(details.winfo_width()*0.31))))

        flows = ttk.Frame(self.tabs)
        box, self.flow_table = table(flows, [
            ("流", 62), ("端点 A", 225), ("端点 B", 225), ("A→B 包/字节", 150),
            ("B→A 包/字节", 150), ("时长", 85), ("状态", 110)], 16)
        tools = ttk.Frame(flows)
        tools.pack(fill="x", pady=5)
        ttk.Button(tools, text="按 IP + 端口查看原文",
                   command=lambda: self.open_stream()).pack(side="left", padx=5)
        ttk.Button(tools, text="按进程查看原文",
                   command=lambda: self.open_stream(by_process=True)).pack(side="left")
        box.pack(expand=True, fill="both")
        self.tabs.add(flows, text="TCP 双向流")
        self.flow_table.bind("<Double-1>", self.pick_flow)
        self.flow_table.bind("<Button-3>", self.flow_menu)
        self.diagnosis = DiagnosisView(self.tabs, table, self.show_frame, self.open_stream)
        self.tabs.add(self.diagnosis, text="进程与会话")
        self.tabs.bind("<<NotebookTabChanged>>", self.tab_changed)
        self.next_chart = 0
        self.chart = tk.Canvas(self.tabs, background="#fbfcff", highlightthickness=0)
        self.tabs.add(self.chart, text="统计")
        self.chart.bind("<Configure>", lambda event: self.draw_chart())
        ttk.Label(content, textvariable=self.metrics).pack(anchor="w")
        ttk.Label(content, textvariable=self.status, wraplength=1150).pack(anchor="w")
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(25, self.poll)
        root.after(100, self.refresh)

    def reset(self):
        self.inspect = Diagnostics()
        self.pause_time = None
        self.pause_flows = set()
        self.capture_counts = Counter()
        self.history = {}
        self.history_bytes = 0
        self.visible = deque()
        self.tracker = FlowTracker()
        self.protocols = Counter()
        self.buckets = Counter()
        self.packet_buckets = Counter()
        self.latest_sec = None
        self.total = 0
        self.selected = None
        self.dirty_flows = set()
        self.ranges = {}
        self.only_flow = None

    def refresh(self):
        self.devices = []
        self.interface.set("")
        try:
            self.backend = Npcap()
            self.devices = self.backend.interfaces()
            self.status.set(f"找到 {len(self.devices)} 个捕获接口。请选择一个接口。")
        except (OSError, RuntimeError) as exc:
            self.status.set(str(exc))
        self.combo.configure(values=[item.label for item in self.devices])
        self.controls()

    def controls(self):
        idle = self.session is None and not self.saving
        for widget in (self.refresh_button, self.open_button, self.demo_button,
                       self.bpf_input):
            widget.configure(state="normal" if idle else "disabled")
        self.combo.configure(state="readonly" if idle else "disabled")
        self.start_button.configure(state="normal" if idle and self.combo.current() >= 0 else "disabled")
        self.stop_button.configure(state="normal" if self.session and not self.session.stop.is_set() else "disabled")
        self.resume_button.configure(state="normal" if idle and self.previous and self.settings else "disabled")
        recording = self.current_recording()
        self.save_button.configure(state="normal" if not self.saving and recording and recording.frames else "disabled")

    def current_recording(self):
        current = self.session or self.previous
        return current.recording if current and current.live else None

    def start_live(self):
        index = self.combo.current()
        if self.session or index < 0:
            return
        device = self.devices[index]
        expression = self.bpf.get().strip()
        if not expression.isascii() or "\x00" in expression:
            messagebox.showerror("捕获 BPF", "BPF 表达式只接受 ASCII 文本。")
            return
        source = self.capture_source(device, expression)
        self.begin(Session(source), f"{device.label}　BPF {expression or '全部'}",
                   settings=(device, expression))

    def capture_source(self, device, expression):
        return lambda stop, submit, ready: self.backend.capture(device, expression, stop, submit, ready)

    def resume(self):
        if not self.previous or not self.settings or self.session or self.saving:
            return
        device, expression = self.settings
        self.interface.set(next((item.label for item in self.devices if item.name == device.name), ""))
        self.bpf.set(expression)
        self.pause_time = self.total + 1
        self.pause_flows = set(self.inspect.conversations)
        self.session = Session(self.capture_source(device, expression), self.previous.recording)
        self.previous = None
        self.controls()
        self.status.set("正在继续捕获")
        self.session.start()

    def open(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap"), ("所有文件", "*.*")])
        if path:
            self.begin(Session(Path(path)), f"离线 · {Path(path).name}")

    def open_demo(self):
        self.begin(Session(BASE / "demo.pcap"), "离线 · 合成示例")

    def begin(self, session, label, settings=None):
        if self.session is not None or self.saving:
            return False
        if not self.release_recording(lambda: self.begin(session, label, settings)):
            return False
        self.settings = settings
        self.reset()
        for tree in (self.packet_table, self.flow_table, self.layers):
            tree.delete(*tree.get_children())
        self.replace_hex("")
        self.metrics.set("")
        self.source_label = label
        self.session = session
        self.status.set(f"正在打开 · {label}")
        self.controls()
        session.start()
        self.tab_changed()
        return True

    def stop(self):
        if self.session:
            self.session.stop.set()
            self.status.set("正在停止并处理队列…")
            self.stop_button.configure(state="disabled")

    def close(self):
        if self.saving:
            return
        if self.session:
            self.closing = True
            self.stop()
        elif self.release_recording(self.root.destroy):
            self.root.destroy()

    def apply(self):
        try:
            self.predicate = display_filter(self.expression.get())
        except ValueError as exc:
            messagebox.showerror("显示过滤", str(exc))
            return
        self.rebuild()

    def clear(self):
        self.only_flow = None
        self.expression.set("")
        self.apply()

    def rebuild(self):
        self.packet_table.delete(*self.visible)
        self.visible.clear()
        for number, (packet, flow) in self.history.items():
            self.insert(number, packet, flow)
        self.update_metrics()

    def insert(self, number, packet, flow):
        if (self.only_flow is not None and flow != self.only_flow) or not self.predicate(packet):
            return
        sec, nanos = divmod(packet.frame.ns, 10**9)
        stamp = datetime.fromtimestamp(sec).strftime("%H:%M:%S") + f".{nanos // 1000:06d}"
        summary = f"{packet.summary}  ⚠ {packet.error}" if packet.error else packet.summary
        self.packet_table.insert("", "end", iid=str(number),
                                 values=(number, stamp, packet.src, packet.dst,
                                         packet.protocol, packet.frame.wire, summary))
        self.visible.append(str(number))

    def accept(self, packet):
        self.total += 1
        flow = self.tracker.update(packet)
        self.inspect.accept(self.total, packet, flow, self.pause_flows)
        if self.pause_time == self.total:
            packet.summary = ("[继续捕获 · 暂停期间未采集] " + packet.summary).strip()
        if flow:
            self.dirty_flows.add(flow)
        self.history[self.total] = (packet, flow)
        self.history_bytes += len(packet.frame.raw)
        while len(self.history) > HISTORY_LIMIT or self.history_bytes > HISTORY_BYTES:
            oldest = next(iter(self.history))
            discarded, _ = self.history.pop(oldest)
            self.history_bytes -= len(discarded.frame.raw)
            if self.visible and self.visible[0] == str(oldest):
                self.packet_table.delete(self.visible.popleft())
        self.insert(self.total, packet, flow)
        self.protocols[packet.protocol] += 1
        sec = packet.frame.ns // 10**9
        if self.latest_sec is None or sec > self.latest_sec:
            self.latest_sec = sec
            for expired in tuple(self.buckets):
                if expired <= sec - 60:
                    del self.buckets[expired]
                    del self.packet_buckets[expired]
        if sec > self.latest_sec - 60:
            self.buckets[sec] += packet.frame.wire
            self.packet_buckets[sec] += 1

    def update_flows(self):
        for flow_id in sorted(self.dirty_flows):
            flow = self.tracker.flows[flow_id]
            values = (flow.id, endpoint(*flow.a), endpoint(*flow.b),
                      f"{flow.packets[0]} / {flow.octets[0]}", f"{flow.packets[1]} / {flow.octets[1]}",
                      f"{(flow.end-flow.start)/1e9:.3f} s", flow.state)
            iid = str(flow.id)
            if self.flow_table.exists(iid):
                self.flow_table.item(iid, values=values)
            else:
                self.flow_table.insert("", "end", iid=iid, values=values)
        self.dirty_flows.clear()

    def pick_flow(self, event):
        row = self.flow_table.identify_row(event.y)
        if row:
            self.only_flow = int(row)
            self.rebuild()
            self.tabs.select(0)

    def packet_menu(self, event):
        row = self.packet_table.identify_row(event.y)
        if row:
            self.packet_table.selection_set(row)
            _, flow = self.history[int(row)]
            if flow:
                self.stream_menu(event, flow)

    def flow_menu(self, event):
        row = self.flow_table.identify_row(event.y)
        if row:
            self.flow_table.selection_set(row)
            self.stream_menu(event, int(row))

    def stream_menu(self, event, flow):
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label="查看此 TCP 流原文", command=lambda: self.open_stream(flow))
        menu.add_command(label="按进程查看 TCP 原文",
                         command=lambda: self.open_stream(flow, by_process=True))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def open_stream(self, flow=None, by_process=False):
        StreamView(self.root, self.tracker.flows, flow, by_process)

    def tab_changed(self, _=None):
        if self.tabs.select() == str(self.diagnosis):
            self.diagnosis.update_data(self.inspect)
        elif self.tabs.select() == str(self.chart):
            self.draw_chart()

    def show_frame(self, number):
        if number not in self.history:
            messagebox.showinfo("定位原包", "该帧已超出列表保留范围，可从保存的 PCAP 离线查找。")
            return
        if not self.packet_table.exists(str(number)):
            self.clear()
        self.packet_table.selection_set(str(number))
        self.packet_table.see(str(number))
        self.tabs.select(0)

    def update_metrics(self):
        flow = f"  ·  流 #{self.only_flow}" if self.only_flow is not None else ""
        self.metrics.set(f"已处理 {self.total:,} 包  ·  列表显示 {len(self.visible):,} 包"
                         f"  ·  保留最近 {len(self.history):,} 包  ·  TCP 流 {len(self.tracker.flows):,}{flow}")

    def poll(self):
        session = self.session
        if session:
            deadline = time.monotonic() + 0.018
            while time.monotonic() < deadline:
                try:
                    packet = session.results.get_nowait()
                except Empty:
                    break
                self.accept(packet)
            self.update_flows()
            self.update_metrics()
            self.controls()
            if self.tabs.select() == str(self.chart) and time.monotonic() >= self.next_chart:
                self.draw_chart()
            elif self.tabs.select() == str(self.diagnosis) and time.monotonic() >= self.diagnosis.next_refresh:
                self.diagnosis.update_data(self.inspect)
            if session.done.is_set() and session.results.empty():
                self.finish(session)
                if self.closing:
                    self.closing = False
                    if self.release_recording(self.root.destroy):
                        self.root.destroy()
                        return
            elif session.link is not None and not session.stop.is_set():
                status = (f"处理中 · {self.source_label} · 收到 {session.received:,}"
                          f" · 队列丢弃 {session.dropped:,}")
                if session.write_error:
                    status += f" · PCAP 写入异常：{session.write_error}"
                if session.owner_warning:
                    status += f" · {session.owner_warning}"
                self.status.set(status)
        self.root.after(45, self.poll)

    def finish(self, session):
        self.session = None
        if session.live:
            self.previous = session
            self.capture_counts["received"] += session.received
            self.capture_counts["dropped"] += session.dropped
            if session.driver_dropped is None:
                self.capture_counts["driver_unknown"] += 1
            else:
                self.capture_counts["driver"] += session.driver_dropped
        state = f"失败 · {session.error}" if session.error else "已停止"
        counts = self.capture_counts
        driver = "部分不可用" if counts["driver_unknown"] else f'{counts["driver"]:,}'
        quality = (f" · 应用接收 {counts['received']:,} · 队列丢弃 {counts['dropped']:,} · 驱动丢包 {driver}"
                   f" · 暂存 {session.recording.frames:,} 帧" if session.live else "")
        status = (f"{state} · {self.source_label}{quality} · 截断 {self.inspect.truncated:,}"
                  f" · 解析问题 {self.inspect.errors:,} · 未解析 {self.inspect.unparsed:,}")
        if session.write_error:
            status += f" · PCAP 写入异常：{session.write_error}"
        if session.owner_warning:
            status += f" · {session.owner_warning}"
        self.status.set(status)
        self.controls()
        self.tab_changed()

    def release_recording(self, continuation):
        """Return true for immediate release, or resume after successful export."""
        if self.previous is None:
            return True
        recording = self.previous.recording
        if recording.dirty:
            answer = messagebox.askyesnocancel(
                "未保存的捕获", "是否保存当前捕获的 PCAP？", parent=self.root)
            if answer is None:
                return False
            if answer:
                self.save_current(continuation)
                return False
        recording.close()
        self.previous = None
        return True

    def save_current(self, continuation=None):
        recording = self.current_recording()
        if not recording or not recording.frames or self.saving:
            return
        length = recording.size
        path = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if not path:
            return
        self.saving = True
        self.controls()
        result = SimpleQueue()

        def write():
            try:
                recording.save(Path(path), length)
            except (OSError, ValueError) as exc:
                result.put(str(exc))
            else:
                result.put(None)

        def complete():
            try:
                error = result.get_nowait()
            except Empty:
                self.root.after(75, complete)
                return
            self.saving = False
            self.controls()
            if error:
                messagebox.showerror("保存失败", error, parent=self.root)
            else:
                self.status.set(f"已保存 {path}" + (" · 捕获继续" if self.session else ""))
                if continuation:
                    recording.close()
                    self.previous = None
                    continuation()

        Thread(target=write, name="PCAP export").start()
        self.root.after(75, complete)

    def show_packet(self, _):
        self.layers.delete(*self.layers.get_children())
        self.ranges.clear()
        rows = self.packet_table.selection()
        self.selected = None
        if not rows or int(rows[0]) not in self.history:
            self.replace_hex("")
            return
        packet, _ = self.history[int(rows[0])]
        self.selected = packet
        frame = packet.frame
        self.layers.insert("", "end", text=f"帧 · 捕获 {len(frame.raw)} B / 原始 {frame.wire} B")
        if packet.error:
            self.layers.insert("", "end", text="解析问题 · " + packet.error)
        for layer in packet.layers:
            node = self.layers.insert("", "end", text=f"{layer.name}  [{layer.start}, {layer.end})", open=True)
            self.ranges[node] = (layer.start, layer.end)
            for key, value in layer.fields.items():
                child = self.layers.insert(node, "end", text=f"{key}  {str(value).replace(chr(13), '').replace(chr(10), ' | ')}")
                self.ranges[child] = self.ranges[node]
        lines = []
        for index in range(0, len(frame.raw), 16):
            chunk = frame.raw[index:index+16]
            ascii_view = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{index:06x}  {chunk.hex(' '):47}  {ascii_view}")
        self.replace_hex("\n".join(lines))

    def replace_hex(self, value):
        self.hexview.configure(state="normal")
        self.hexview.delete("1.0", "end")
        self.hexview.insert("1.0", value)
        self.hexview.configure(state="disabled")

    def highlight(self, _):
        self.hexview.tag_remove("layer", "1.0", "end")
        rows = self.layers.selection()
        if not rows or rows[0] not in self.ranges:
            return
        start, end = self.ranges[rows[0]]
        for row in range(start // 16, (end + 15) // 16):
            lo = max(start - row * 16, 0)
            hi = min(end - row * 16, 16)
            self.hexview.tag_add("layer", f"{row+1}.{8+3*lo}", f"{row+1}.{7+3*hi}")
            self.hexview.tag_add("layer", f"{row+1}.{57+lo}", f"{row+1}.{57+hi}")
        self.hexview.see(f"{start//16+1}.0")

    def draw_chart(self):
        self.next_chart = time.monotonic() + 0.5
        c = self.chart
        c.delete("all")
        width = max(c.winfo_width(), 600)
        c.create_text(25, 24, anchor="w", text="吞吐量 · 最近 60 个捕获秒 · 原始帧字节/秒",
                      font=("Microsoft YaHei UI", 12, "bold"))
        last = self.latest_sec or 0
        values = [self.buckets[sec] for sec in range(last-59, last+1)]
        peak = max(max(values), 1)
        step = (width - 60) / 60
        c.create_line(25, 200, width-35, 200, fill="#9ba7b8")
        for i, count in enumerate(values):
            if count:
                x = 25 + i * step
                c.create_rectangle(x, 199 - 142*count/peak, x+step*0.8, 199,
                                   fill="#237a9f", outline="")
        pps = [self.packet_buckets[sec] for sec in range(last-59, last+1)]
        pps_peak = max(max(pps), 1)
        dots = [coordinate for i, count in enumerate(pps)
                for coordinate in (25 + (i+0.4)*step, 199 - 142*count/pps_peak)]
        c.create_line(*dots, fill="#b36516", width=2)
        c.create_text(width-35, 24, anchor="e", text="蓝柱 帧字节/秒 · 橙线 包/秒（各按自身峰值缩放）")
        c.create_text(25, 218, anchor="w", text=f"窗口峰值 {max(values):,} B/s · {max(self.packet_buckets.values(), default=0):,} 包/s")
        c.create_text(25, 258, anchor="w", text="协议分布 · 按每包最深识别层统计",
                      font=("Microsoft YaHei UI", 12, "bold"))
        for i, (name, count) in enumerate(self.protocols.most_common(9)):
            y = 281 + 23*i
            c.create_text(25, y+8, anchor="w", text=name)
            size = (width-225)*count/max(self.total, 1)
            c.create_rectangle(143, y, 143+size, y+16, fill="#49a58c", outline="")
            c.create_text(150+size, y+8, anchor="w", text=f"{count:,}")


def main():
    if hasattr(ctypes, "windll"):
        ctypes.windll.user32.SetProcessDPIAware()
    root = tk.Tk()
    App(root)
    root.mainloop()



if __name__ == "__main__":
    main()
