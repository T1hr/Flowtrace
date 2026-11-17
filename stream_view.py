"""TCP stream reader with endpoint and process-based navigation."""
import tkinter as tk
from tkinter import ttk

from analysis_core import endpoint
from tcp_stream import DISPLAY_BYTES, readable, reassemble


class StreamView(tk.Toplevel):
    def __init__(self, parent, flows, initial=None, by_process=False):
        super().__init__(parent)
        self.title("查看 TCP 流原文")
        self.geometry("900x620")
        self.minsize(680, 460)
        self.flows = flows
        self.initial = initial
        self.processes = {}
        if by_process:
            for flow in flows.values():
                for owner in flow.owners[0] | flow.owners[1]:
                    self.processes.setdefault(owner, []).append(flow.id)

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        if by_process:
            self.process = self.choice(outer, "进程", [
                f"{name} · PID {pid}" for pid, name in self.processes], self.choose_process)
        self.flow = self.choice(outer, "TCP 流", [], self.render)
        self.direction = self.choice(outer, "发送方向", ["双向", "A → B", "B → A"], self.render)
        self.mode = self.choice(outer, "显示格式", ["文本 (UTF-8)", "十六进制"], self.render)
        self.note = ttk.Label(outer, wraplength=630)
        self.note.pack(anchor="w", pady=6)
        box = ttk.Frame(outer)
        box.pack(fill="both", expand=True)
        self.content = tk.Text(box, wrap="char", font=("Consolas", 11), state="disabled")
        bar = ttk.Scrollbar(box, command=self.content.yview)
        self.content.configure(yscrollcommand=bar.set)
        self.content.tag_configure("a", foreground="#912923", background="#fff0ee")
        self.content.tag_configure("b", foreground="#163f8b", background="#eaf2ff")
        self.content.tag_configure("note", foreground="#565e6e")
        self.content.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")

        if by_process and self.processes:
            index = next((i for i, ids in enumerate(self.processes.values())
                          if initial in ids), 0)
            self.process.current(index)
            self.choose_process()
        elif by_process:
            self.note.configure(text="当前会话没有匹配到本机进程。请在实时捕获时尝试，普通 PCAP 没有 PID。")
        else:
            self.set_flows(sorted(flows))

    def choice(self, parent, label, values, callback):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=10).pack(side="left")
        combo = ttk.Combobox(row, values=values, state="readonly")
        combo.pack(side="left", fill="x", expand=True)
        if values:
            combo.current(0)
        combo.bind("<<ComboboxSelected>>", callback)
        return combo

    def set_flows(self, ids):
        self.ids = ids
        self.flow.configure(values=[
            f"#{i}  {endpoint(*self.flows[i].a)}  ↔  {endpoint(*self.flows[i].b)}" for i in ids])
        if ids:
            self.flow.current(ids.index(self.initial) if self.initial in ids else 0)
            self.render()
        else:
            self.note.configure(text="当前会话没有 TCP 流。")

    def choose_process(self, _=None):
        ids = list(self.processes.values())[self.process.current()]
        self.set_flows(sorted(ids))

    def render(self, _=None):
        index = self.flow.current()
        if index < 0:
            return
        flow = self.flows[self.ids[index]]
        self.note.configure(text="A 用红色，B 用蓝色。内容按各方向的 TCP 序号拼接。加密数据可切换到十六进制。")
        self.content.configure(state="normal")
        self.content.delete("1.0", "end")
        choice = self.direction.current()
        for direction in (0, 1):
            if choice and direction != choice - 1:
                continue
            who = "A" if direction == 0 else "B"
            address = (flow.a, flow.b)[direction]
            names = ", ".join(f"{name} (PID {pid})" for pid, name in sorted(flow.owners[direction]))
            label = f"{who} → {'B' if direction == 0 else 'A'}  {endpoint(*address)}"
            if names:
                label += f"  ·  {names}"
            tag = who.lower()
            self.content.insert("end", label + "\n", tag)
            remaining = DISPLAY_BYTES
            if not flow.segments[direction]:
                self.content.insert("end", "[无可见负载]\n", "note")
            elif flow.origins[direction] is None:
                self.content.insert("end", "[未见握手，起点可能不完整]\n", "note")
            for part in reassemble(flow.segments[direction], flow.origins[direction]):
                if isinstance(part, int):
                    self.content.insert("end", f"\n[缺失 {part:,} 字节]\n", "note")
                    continue
                self.content.insert("end", readable(part[:remaining], self.mode.current() == 1), tag)
                remaining -= len(part)
                if remaining <= 0:
                    self.content.insert("end", "\n[达到单方向显示上限]\n", "note")
                    break
            if flow.stream_limited[direction]:
                self.content.insert("end", "\n[达到会话重组缓存上限]\n", "note")
            self.content.insert("end", "\n\n")
        self.content.configure(state="disabled")

