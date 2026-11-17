"""Drill down from process totals to endpoint conversations and packet arrows."""
from collections import Counter
import time
import tkinter as tk
from tkinter import ttk

from analysis_core import endpoint


class DiagnosisView(ttk.Frame):
    def __init__(self, parent, table, show_frame, open_stream):
        super().__init__(parent, padding=8)
        self.show_frame = show_frame
        self.open_stream = open_stream
        self.next_refresh = 0
        self.data = None
        self.selected_key = None
        self.protocol = tk.StringVar(value="全部")
        self.target = tk.StringVar()
        self.process = tk.StringVar(value="全部进程")
        self.summary = tk.StringVar()
        self.selected = tk.StringVar(value="选择一条会话查看交互")
        tools = ttk.Frame(self)
        tools.pack(fill="x")
        ttk.Label(tools, text="进程").pack(side="left")
        self.process_box = ttk.Combobox(tools, textvariable=self.process, state="readonly", width=29)
        self.process_box.pack(side="left", padx=5)
        ttk.Label(tools, text="协议").pack(side="left")
        protocols = ttk.Combobox(tools, state="readonly", textvariable=self.protocol,
                                 values=("全部", "TCP", "UDP"), width=7)
        protocols.pack(side="left", padx=5)
        for choice in (self.process_box, protocols):
            choice.bind("<<ComboboxSelected>>", self.filter_changed)
        ttk.Label(tools, text="IP 或端口").pack(side="left", padx=(12, 0))
        needle = ttk.Entry(tools, textvariable=self.target, width=22)
        needle.pack(side="left", padx=5)
        needle.bind("<Return>", self.filter_changed)
        ttk.Button(tools, text="筛选", command=self.filter_changed).pack(side="left")
        self.stream_button = ttk.Button(tools, text="流原文", command=self.stream, state="disabled")
        self.stream_button.pack(side="right")
        ttk.Label(self, textvariable=self.summary).pack(anchor="w", pady=5)

        split = ttk.Panedwindow(self, orient="horizontal")
        split.pack(fill="both", expand=True)
        left = ttk.Panedwindow(split, orient="vertical")
        split.add(left, weight=5)
        box, self.process_table = table(left, [
            ("进程", 145), ("发送", 54), ("接收", 54), ("字节", 70), ("主要协议", 120)], 5)
        left.add(box, weight=1)
        self.process_table.bind("<Double-1>", self.pick_process)
        box, self.sessions = table(left, [
            ("协议", 59), ("端点 A", 160), ("端点 B", 160), ("包", 55), ("状态", 155)], 14)
        left.add(box, weight=3)
        self.sessions.tag_configure("error", foreground="#9d251d", background="#fff1ed")
        self.sessions.tag_configure("warn", foreground="#864c00", background="#fffaed")
        self.sessions.bind("<<TreeviewSelect>>", self.choose)

        panel = ttk.Frame(split, padding=(8, 0))
        split.add(panel, weight=6)
        split.bind("<Map>", lambda event: split.after_idle(
            lambda: split.sashpos(0, int(split.winfo_width()*0.53))))
        ttk.Label(panel, textvariable=self.selected, wraplength=530).pack(fill="x", pady=(0, 4))
        self.canvas = tk.Canvas(panel, background="#f4f7fb", highlightthickness=0)
        bar = ttk.Scrollbar(panel, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        self.canvas.bind("<Configure>", lambda event: self.draw(keep=True))
        self.canvas.bind("<MouseWheel>", lambda event: self.canvas.yview_scroll(-event.delta//120, "units"))
        self.row_keys = {}
        self.process_names = {}
        self.last_draw = None

    def update_data(self, data):
        if self.data is not data:
            self.selected_key = None
            self.last_draw = None
        self.data = data
        self.next_refresh = time.monotonic() + 1
        grouped = {}
        for (pid, name), traffic in data.processes.items():
            grouped.setdefault(name, []).append((pid, traffic))
        self.process_names = {"全部进程": None, "归属不明": set()}
        self.process_table.delete(*self.process_table.get_children())
        for name, rows in sorted(grouped.items(), key=lambda item: -sum(t.packets for _, t in item[1])):
            self.process_names[name] = {(pid, name) for pid, _ in rows}
            self.add_process(name, [t for _, t in rows])
            for pid, traffic in sorted(rows):
                label = f"{name} · PID {pid}"
                self.process_names[label] = {(pid, name)}
                self.add_process(label, [traffic])
        self.process_box.configure(values=tuple(self.process_names))
        if self.process.get() not in self.process_names:
            self.process.set("全部进程")
        ratio = f"{(data.eligible-data.unknown)/data.eligible:.1%}" if data.eligible else "—"
        self.summary.set(f"TCP/UDP 归属覆盖 {ratio} · 归属不明 {data.unknown:,}/{data.eligible:,} 包"
                         " · 双击进程筛选会话，点击箭头查看原包")
        self.build_sessions()

    def add_process(self, label, traffic):
        counts = Counter()
        for row in traffic:
            counts.update(row.protocols)
        self.process_table.insert("", "end", values=(
            label, sum(t.sent for t in traffic), sum(t.received for t in traffic),
            f"{sum(t.octets for t in traffic):,}",
            " / ".join(f"{name} {num}" for name, num in counts.most_common(3))))

    def pick_process(self, event):
        row = self.process_table.identify_row(event.y)
        if row:
            self.process.set(self.process_table.item(row, "values")[0])
            self.build_sessions()

    def filter_changed(self, _=None):
        if self.data is not None:
            self.build_sessions()

    def build_sessions(self):
        wanted = self.process_names.get(self.process.get())
        protocol = self.protocol.get()
        needle = self.target.get().strip().strip("[]").lower()
        self.sessions.delete(*self.sessions.get_children())
        self.row_keys.clear()
        for key, flow in self.data.conversations.items():
            if protocol not in ("全部", flow.protocol):
                continue
            if wanted is not None and (not (flow.owners & wanted) if wanted else bool(flow.owners)):
                continue
            if needle and not any(needle == str(port) or needle in addr.lower() or needle == endpoint(addr, port).lower()
                                  for addr, port in (flow.a, flow.b)):
                continue
            tag = "error" if flow.reset else "warn" if flow.syn and not flow.reply else ""
            row = self.sessions.insert("", "end", values=(
                flow.protocol, endpoint(*flow.a), endpoint(*flow.b), flow.count, flow.state), tags=(tag,))
            self.row_keys[row] = key
            if key == self.selected_key:
                self.sessions.selection_set(row)
                self.sessions.see(row)
        if self.row_keys and self.selected_key not in self.row_keys.values():
            self.sessions.selection_set(next(iter(self.row_keys)))
        if not self.row_keys:
            self.selected_key = None
        self.choose()

    def choose(self, _=None):
        rows = self.sessions.selection()
        self.selected_key = self.row_keys.get(rows[0]) if rows else None
        self.draw()

    def stream(self):
        if self.selected_key and self.selected_key[0] == "TCP":
            self.open_stream(self.selected_key[3])

    def draw(self, keep=False):
        key = self.selected_key
        flow = self.data.conversations.get(key) if self.data and key else None
        signature = key, flow.count if flow else 0, self.canvas.winfo_width()
        if signature == self.last_draw and not keep:
            return
        old_key = self.last_draw[0] if self.last_draw else None
        self.last_draw = signature
        position = self.canvas.yview()[0] if key == old_key else 0.0
        c = self.canvas
        c.delete("all")
        self.stream_button.configure(state="normal" if flow and flow.protocol == "TCP" else "disabled")
        if not flow:
            self.selected.set("选择一条会话查看交互")
            return
        duration = max(0, (flow.end-flow.start)/1e6)
        self.selected.set(f"{flow.protocol} · {flow.state} · {flow.count} 包 · {duration:.2f} ms"
                          + (f" · 跨 {flow.gaps} 次暂停" if flow.gaps else ""))
        width = max(c.winfo_width(), 325)
        left, right = 66, width-66
        c.create_text(8, 12, anchor="nw", text="A  " + endpoint(*flow.a), fill="#15324a")
        c.create_text(width-8, 31, anchor="ne", text="B  " + endpoint(*flow.b), fill="#15324a")
        events = [*flow.first, *flow.latest]
        if flow.events_seen > len(events):
            omitted = flow.events_seen - len(events)
            self.selected.set(self.selected.get() + f" · 中段省略 {omitted:,} 个事件")
        height = 72 + len(events)*42
        for x in (left, right):
            c.create_line(x, 53, x, height, fill="#a7b6c9", dash=(3, 4))
        for i, event in enumerate(events):
            y = 76 + i*42
            key_tag = f"frame_{i}"
            palette = {"error": "#b3212d", "warn": "#965009"}
            color = palette.get(event.severity, "#157559" if event.side == 0 else "#285da4")
            start, finish = (left, right) if event.side == 0 else (right, left)
            c.create_line(start, y, finish, y, arrow="last", width=2, fill=color, tags=(key_tag,))
            elapsed = (event.ns-flow.start)/1e6
            c.create_text((left+right)/2, y-10, text=f"#{event.number}  +{elapsed:.2f} ms",
                          fill=color, tags=(key_tag,))
            text = event.label if len(event.label) < 64 else event.label[:61] + "…"
            c.create_text((left+right)/2, y+11, text=text, fill=color, tags=(key_tag,))
            c.tag_bind(key_tag, "<Button-1>", lambda _, n=event.number: self.show_frame(n))
        c.configure(scrollregion=(0, 0, width, height+15))
        c.yview_moveto(position)

