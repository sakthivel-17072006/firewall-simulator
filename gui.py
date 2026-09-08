"""
gui.py
Tkinter GUI for the Simple Firewall Rule Simulator.
Run:  python gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading

from firewall_engine import FirewallEngine
from live_capture import LiveCapture, SCAPY_AVAILABLE

# ── Colour palette ──────────────────────────
BG       = "#0d1117"
SURFACE  = "#161b22"
BORDER   = "#30363d"
FG       = "#e6edf3"
FG_DIM   = "#8b949e"
GREEN    = "#3fb950"
RED      = "#f85149"
YELLOW   = "#d29922"
BLUE     = "#58a6ff"
PURPLE   = "#bc8cff"

FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_H1   = ("Segoe UI", 14, "bold")
FONT_H2   = ("Segoe UI", 11, "bold")

PROTOCOLS  = ["TCP", "UDP", "ICMP", "ANY"]
DIRECTIONS = ["INBOUND", "OUTBOUND", "ANY"]
ACTIONS    = ["ALLOW", "BLOCK"]


# ── Helpers ──────────────────────────────────
def style_widget(w, bg=SURFACE, fg=FG, font=FONT_UI):
    try:
        w.configure(bg=bg, fg=fg, font=font,
                    insertbackground=FG, relief="flat",
                    highlightthickness=1, highlightbackground=BORDER,
                    highlightcolor=BLUE)
    except Exception:
        pass


def entry(parent, width=18, **kw) -> tk.Entry:
    e = tk.Entry(parent, width=width, bg=SURFACE, fg=FG,
                 insertbackground=FG, font=FONT_UI, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=BLUE, **kw)
    return e


def combo(parent, values, width=12) -> ttk.Combobox:
    c = ttk.Combobox(parent, values=values, width=width,
                     state="readonly", font=FONT_UI)
    c.current(0)
    return c


def label(parent, text, fg=FG, font=FONT_UI, bg=BG, **kw) -> tk.Label:
    return tk.Label(parent, text=text, bg=bg, fg=fg,
                    font=font, **kw)


def btn(parent, text, cmd, color=BLUE, width=12) -> tk.Button:
    return tk.Button(
        parent, text=text, command=cmd,
        bg=color, fg="#ffffff", font=("Segoe UI", 10, "bold"),
        activebackground=color, activeforeground="#ffffff",
        relief="flat", cursor="hand2", padx=8, pady=4,
        width=width
    )


# ── Main Application ─────────────────────────
class FirewallApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.engine = FirewallEngine()
        self.live_capture = LiveCapture(self.engine)
        self.title("🔥 Firewall Rule Simulator")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.geometry("1100x750")

        self._apply_ttk_style()
        self._build_ui()
        self._refresh_rules()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.live_capture.stop()
        self.destroy()

    # ── TTK theming ──────────────────────────
    def _apply_ttk_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        
        style.configure("TNotebook.Tab",
                background="#d1d5da",   # light background
                foreground="black",
                padding=[10, 5],
                font=("Segoe UI", 10, "bold"))

        style.map("TNotebook.Tab",
          background=[("selected", "#ffffff")],
          foreground=[("selected", "black")])
        style.configure(".", background=SURFACE, foreground=FG,
                        fieldbackground=SURFACE, troughcolor=BORDER,
                        selectbackground=BLUE, selectforeground="#fff")
        style.configure("Treeview", background=SURFACE, foreground=FG,
                        fieldbackground=SURFACE, rowheight=26,
                        font=FONT_UI)
        style.configure("Treeview.Heading", background=BORDER,
                        foreground=FG, font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#1f6feb")])
        style.configure("TCombobox", fieldbackground=SURFACE,
                        background=SURFACE, foreground=FG,
                        arrowcolor=FG)
        style.map("TCombobox", fieldbackground=[("readonly", SURFACE)])

    # ── Layout ──────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg="#161b22", pady=10)
        hdr.pack(fill="x", padx=0)
        tk.Label(hdr, text="🔥  FIREWALL RULE SIMULATOR",
                 bg="#161b22", fg=BLUE, font=("Courier New", 16, "bold")).pack(side="left", padx=18)
        tk.Label(hdr, text="stateless packet filter  •  first-match wins",
                 bg="#161b22", fg=FG_DIM, font=FONT_UI).pack(side="left")

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=8)

        self.tab_rules   = tk.Frame(nb, bg=BG)
        self.tab_packet  = tk.Frame(nb, bg=BG)
        self.tab_live    = tk.Frame(nb, bg=BG)
        self.tab_log     = tk.Frame(nb, bg=BG)

        nb.add(self.tab_rules,  text="  📋  Rules Manager  ")
        nb.add(self.tab_packet, text="  📡  Packet Simulator  ")
        nb.add(self.tab_live,   text="  🛰️  Live Capture  ")
        nb.add(self.tab_log,    text="  📄  Decision Log  ")

        self._build_rules_tab()
        self._build_packet_tab()
        self._build_live_tab()
        self._build_log_tab()

    # ────────────────────────────────────────
    # TAB 1 — Rules Manager
    # ────────────────────────────────────────
    def _build_rules_tab(self):
        t = self.tab_rules

        # ── Treeview ──
        cols = ("Priority", "Source IP", "Dest Port", "Protocol",
                "Direction", "Action", "Description")
        tree_frame = tk.Frame(t, bg=BG)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(12, 4))

        self.tree = ttk.Treeview(tree_frame, columns=cols,
                                  show="headings", selectmode="browse")
        widths = [70, 140, 90, 90, 100, 80, 300]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="center" if w < 200 else "w")

        sb = ttk.Scrollbar(tree_frame, orient="vertical",
                           command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree.tag_configure("ALLOW", foreground=GREEN)
        self.tree.tag_configure("BLOCK", foreground=RED)

        # ── Rule Form ──
        form_outer = tk.Frame(t, bg=SURFACE, padx=14, pady=12,
                              highlightthickness=1,
                              highlightbackground=BORDER)
        form_outer.pack(fill="x", padx=12, pady=6)

        label(form_outer, "ADD / EDIT RULE", fg=BLUE,
              font=FONT_H2, bg=SURFACE).grid(row=0, column=0,
              columnspan=8, sticky="w", pady=(0, 8))

        fields = [
            ("Priority",    "e_priority",   None),
            ("Source IP",   "e_src_ip",     None),
            ("Dest Port",   "e_dest_port",  None),
            ("Protocol",    "cb_proto",     PROTOCOLS),
            ("Direction",   "cb_dir",       DIRECTIONS),
            ("Action",      "cb_action",    ACTIONS),
            ("Description", "e_desc",       None),
        ]

        col = 0
        for lbl_text, attr, opts in fields:
            tk.Label(form_outer, text=lbl_text, bg=SURFACE,
                     fg=FG_DIM, font=FONT_UI).grid(
                row=1, column=col, sticky="w", padx=(0, 4))
            if opts:
                w = combo(form_outer, opts,
                          width=10 if lbl_text != "Direction" else 11)
            else:
                w_width = 28 if lbl_text == "Description" else 14
                w = entry(form_outer, width=w_width)
            w.grid(row=2, column=col, padx=(0, 8), pady=2, sticky="w")
            setattr(self, attr, w)
            col += 1

        # buttons row
        btn_frame = tk.Frame(form_outer, bg=SURFACE)
        btn_frame.grid(row=3, column=0, columnspan=8, pady=(10, 2), sticky="w")
        btn(btn_frame, "➕ Add Rule",    self._add_rule,    GREEN,  10).pack(side="left", padx=(0, 6))
        btn(btn_frame, "✏️ Update Rule", self._update_rule,  BLUE,  11).pack(side="left", padx=(0, 6))
        btn(btn_frame, "🗑️ Delete Rule", self._delete_rule,  RED,   11).pack(side="left", padx=(0, 6))
        btn(btn_frame, "↩ Reset Defaults", self._reset_defaults, YELLOW, 14).pack(side="left", padx=(0, 6))

        self.tree.bind("<<TreeviewSelect>>", self._on_rule_select)

    # ────────────────────────────────────────
    # TAB 2 — Packet Simulator
    # ────────────────────────────────────────
    def _build_packet_tab(self):
        t = self.tab_packet

        # Form card
        card = tk.Frame(t, bg=SURFACE, padx=20, pady=18,
                        highlightthickness=1,
                        highlightbackground=BORDER)
        card.pack(padx=20, pady=16, fill="x")

        label(card, "SIMULATE A PACKET", fg=BLUE,
              font=FONT_H1, bg=SURFACE).grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 12))

        pfields = [
            ("Source IP",      "p_src_ip",   None,        "192.168.1.100"),
            ("Destination IP", "p_dest_ip",  None,        "10.0.0.1"),
            ("Source Port",    "p_src_port", None,        "54321"),
            ("Dest Port",      "p_dest_port",None,        "80"),
            ("Protocol",       "p_proto",    PROTOCOLS,   None),
            ("Direction",      "p_dir",      DIRECTIONS,  None),
        ]

        for i, (lbl_text, attr, opts, default) in enumerate(pfields):
            r, c = divmod(i, 3)
            tk.Label(card, text=lbl_text, bg=SURFACE,
                     fg=FG_DIM, font=FONT_UI).grid(
                row=r*2+1, column=c, sticky="w", padx=(0,6), pady=(6,0))
            if opts:
                w = combo(card, opts, width=14)
            else:
                w = entry(card, width=18)
                if default:
                    w.insert(0, default)
            w.grid(row=r*2+2, column=c, sticky="w", padx=(0,24))
            setattr(self, attr, w)

        btn(card, "🚀 Fire Packet!", self._simulate_packet,
            PURPLE, 16).grid(row=6, column=0, columnspan=3,
                              pady=(16, 4), sticky="w")

        # Verdict panel
        vcard = tk.Frame(t, bg=SURFACE, padx=20, pady=16,
                         highlightthickness=1,
                         highlightbackground=BORDER)
        vcard.pack(padx=20, pady=4, fill="x")

        tk.Label(vcard, text="VERDICT", bg=SURFACE,
                 fg=FG_DIM, font=("Segoe UI", 9, "bold")).pack(anchor="w")

        self.verdict_var = tk.StringVar(value="— fire a packet to see the result —")
        self.verdict_lbl = tk.Label(vcard, textvariable=self.verdict_var,
                                    bg=SURFACE, fg=FG_DIM,
                                    font=("Courier New", 14, "bold"),
                                    wraplength=800, justify="left")
        self.verdict_lbl.pack(anchor="w", pady=(6, 2))

        self.match_var = tk.StringVar(value="")
        tk.Label(vcard, textvariable=self.match_var,
                 bg=SURFACE, fg=FG_DIM,
                 font=FONT_UI, wraplength=800,
                 justify="left").pack(anchor="w")

    # ────────────────────────────────────────
    # TAB 3 — Live Capture
    # ────────────────────────────────────────
    def _build_live_tab(self):
        t = self.tab_live

        ctrl = tk.Frame(t, bg=SURFACE, padx=16, pady=12,
                        highlightthickness=1, highlightbackground=BORDER)
        ctrl.pack(fill="x", padx=12, pady=(12, 6))

        label(ctrl, "LIVE NETWORK CAPTURE", fg=BLUE, font=FONT_H1,
              bg=SURFACE).grid(row=0, column=0, columnspan=6,
                                sticky="w", pady=(0, 10))

        tk.Label(ctrl, text="Interface (blank = default)", bg=SURFACE,
                 fg=FG_DIM, font=FONT_UI).grid(row=1, column=0, sticky="w")
        self.e_iface = entry(ctrl, width=22)
        self.e_iface.grid(row=2, column=0, padx=(0, 16), sticky="w")

        tk.Label(ctrl, text="BPF Filter", bg=SURFACE,
                 fg=FG_DIM, font=FONT_UI).grid(row=1, column=1, sticky="w")
        self.e_bpf = entry(ctrl, width=22)
        self.e_bpf.insert(0, "ip")
        self.e_bpf.grid(row=2, column=1, padx=(0, 16), sticky="w")

        self.btn_start_live = btn(ctrl, "▶ Start Sniffing", self._start_live,
                                   GREEN, 16)
        self.btn_start_live.grid(row=2, column=2, padx=(0, 8))

        self.btn_stop_live = btn(ctrl, "⏹ Stop", self._stop_live, RED, 10)
        self.btn_stop_live.grid(row=2, column=3, padx=(0, 8))
        self.btn_stop_live.configure(state="disabled")

        self.live_status_var = tk.StringVar(
            value="● STOPPED" if SCAPY_AVAILABLE
            else "⚠ scapy not installed — run: pip install scapy")
        tk.Label(ctrl, textvariable=self.live_status_var, bg=SURFACE,
                 fg=FG_DIM, font=("Segoe UI", 10, "bold")).grid(
            row=2, column=4, padx=(8, 0))

        note = ("Requires admin/root privileges (Npcap on Windows). "
                "Passively evaluates real traffic against your rules "
                "and logs ALLOW/BLOCK verdicts — does not modify OS routing.")
        tk.Label(ctrl, text=note, bg=SURFACE, fg=FG_DIM,
                 font=("Segoe UI", 8), wraplength=900,
                 justify="left").grid(row=3, column=0, columnspan=6,
                                       sticky="w", pady=(8, 0))

        # Stats strip
        stats = tk.Frame(t, bg=BG)
        stats.pack(fill="x", padx=12, pady=4)
        self.live_total_var = tk.StringVar(value="Total: 0")
        self.live_allow_var = tk.StringVar(value="Allowed: 0")
        self.live_block_var = tk.StringVar(value="Blocked: 0")
        tk.Label(stats, textvariable=self.live_total_var, bg=BG, fg=FG,
                 font=FONT_H2).pack(side="left", padx=(0, 20))
        tk.Label(stats, textvariable=self.live_allow_var, bg=BG, fg=GREEN,
                 font=FONT_H2).pack(side="left", padx=(0, 20))
        tk.Label(stats, textvariable=self.live_block_var, bg=BG, fg=RED,
                 font=FONT_H2).pack(side="left")

        # Live feed
        self.live_text = scrolledtext.ScrolledText(
            t, font=FONT_MONO, bg="#010409", fg=FG_DIM,
            insertbackground=FG, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            state="disabled"
        )
        self.live_text.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        self.live_text.tag_configure("ALLOW", foreground=GREEN)
        self.live_text.tag_configure("BLOCK", foreground=RED)
        self.live_text.tag_configure("ERR",   foreground=YELLOW)

        if not SCAPY_AVAILABLE:
            self.btn_start_live.configure(state="disabled")

        # start the periodic queue poller (runs regardless of capture state)
        self.after(300, self._poll_live_queue)

    def _start_live(self):
        iface = self.e_iface.get().strip() or None
        bpf = self.e_bpf.get().strip() or "ip"
        self.live_capture.iface = iface
        self.live_capture.bpf_filter = bpf
        ok = self.live_capture.start()
        if ok:
            self.live_status_var.set("● CAPTURING…")
            self.btn_start_live.configure(state="disabled")
            self.btn_stop_live.configure(state="normal")

    def _stop_live(self):
        self.live_capture.stop()
        self.live_status_var.set("● STOPPED")
        self.btn_start_live.configure(state="normal" if SCAPY_AVAILABLE else "disabled")
        self.btn_stop_live.configure(state="disabled")

    def _poll_live_queue(self):
        items = self.live_capture.poll()
        if items:
            self.live_text.configure(state="normal")
            for item in items:
                if "error" in item:
                    self.live_text.insert("end", f"[!] {item['error']}\n", "ERR")
                    self.live_status_var.set("● ERROR")
                    self.btn_start_live.configure(state="normal" if SCAPY_AVAILABLE else "disabled")
                    self.btn_stop_live.configure(state="disabled")
                    continue
                p = item["packet"]
                tag = "ALLOW" if item["action"] == "ALLOW" else "BLOCK"
                src_host = p.get("src_host", p["src_ip"])
                dest_host = p.get("dest_host", p["dest_ip"])
                # Only show "(hostname)" when it actually resolved to
                # something different from the raw IP — keeps the line
                # readable instead of repeating the IP twice.
                src_label = (f"{p['src_ip']} ({src_host})"
                             if src_host != p["src_ip"] else p["src_ip"])
                dest_label = (f"{p['dest_ip']} ({dest_host})"
                              if dest_host != p["dest_ip"] else p["dest_ip"])
                line = (f"[{item['timestamp']}] {item['action']:5s} | "
                        f"{src_label}:{p['src_port']} -> "
                        f"{dest_label}:{p['dest_port']} | "
                        f"{p['protocol']:5s} | {p['direction']:8s} | "
                        f"{item['matched_rule']}\n")
                self.live_text.insert("end", line, tag)
            self.live_text.see("end")
            self.live_text.configure(state="disabled")

            self.live_total_var.set(f"Total: {self.live_capture.stats['total']}")
            self.live_allow_var.set(f"Allowed: {self.live_capture.stats['allow']}")
            self.live_block_var.set(f"Blocked: {self.live_capture.stats['block']}")

            # keep the Decision Log tab in sync too
            self._refresh_log()

        self.after(300, self._poll_live_queue)

    # ────────────────────────────────────────
    # TAB 4 — Decision Log
    # ────────────────────────────────────────
    def _build_log_tab(self):
        t = self.tab_log

        ctrl = tk.Frame(t, bg=BG)
        ctrl.pack(fill="x", padx=12, pady=8)
        btn(ctrl, "🔄 Refresh", self._refresh_log, BLUE,    9).pack(side="left", padx=(0, 8))
        btn(ctrl, "🗑️ Clear Log", self._clear_log, RED,    10).pack(side="left")

        self.log_text = scrolledtext.ScrolledText(
            t, font=FONT_MONO, bg="#010409", fg=FG_DIM,
            insertbackground=FG, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            state="disabled"
        )
        self.log_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.log_text.tag_configure("ALLOW", foreground=GREEN)
        self.log_text.tag_configure("BLOCK", foreground=RED)
        self.log_text.tag_configure("DIM",   foreground=FG_DIM)

        self._refresh_log()

    # ────────────────────────────────────────
    # Rule operations
    # ────────────────────────────────────────
    def _collect_form(self) -> dict | None:
        try:
            priority = int(self.e_priority.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Priority must be an integer.")
            return None
        src_ip    = self.e_src_ip.get().strip()   or "ANY"
        dest_port = self.e_dest_port.get().strip() or "ANY"
        protocol  = self.cb_proto.get()
        direction = self.cb_dir.get()
        action    = self.cb_action.get()
        desc      = self.e_desc.get().strip()
        return dict(priority=priority, src_ip=src_ip,
                    dest_port=dest_port, protocol=protocol,
                    direction=direction, action=action,
                    description=desc)

    def _add_rule(self):
        rule = self._collect_form()
        if rule is None:
            return
        self.engine.add_rule(rule)
        self._refresh_rules()
        self._clear_form()

    def _update_rule(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a rule to update.")
            return
        rule_id = self.tree.item(sel[0])["values"][0]
        # priority is column 0 but id is stored as iid tag
        rule_id = self._selected_id
        rule = self._collect_form()
        if rule is None:
            return
        self.engine.update_rule(rule_id, rule)
        self._refresh_rules()

    def _delete_rule(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a rule to delete.")
            return
        if messagebox.askyesno("Confirm", "Delete selected rule?"):
            self.engine.delete_rule(self._selected_id)
            self._refresh_rules()
            self._clear_form()

    def _reset_defaults(self):
        from firewall_engine import DEFAULT_RULES, save_rules
        if messagebox.askyesno("Reset", "Restore factory default rules?"):
            save_rules(DEFAULT_RULES)
            self.engine.reload()
            self._refresh_rules()

    def _on_rule_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])["values"]
        # vals: Priority, Src IP, Dest Port, Protocol, Direction, Action, Desc
        self._selected_id = self.tree.item(sel[0])["tags"][0]

        for widget, val in [
            (self.e_priority,  vals[0]),
            (self.e_src_ip,    vals[1]),
            (self.e_dest_port, vals[2]),
            (self.e_desc,      vals[6]),
        ]:
            widget.delete(0, "end")
            widget.insert(0, val)

        self.cb_proto.set(vals[3])
        self.cb_dir.set(vals[4])
        self.cb_action.set(vals[5])

    def _refresh_rules(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for rule in sorted(self.engine.rules, key=lambda r: r.get("priority", 9999)):
            tag = rule["action"].upper()
            self.tree.insert("", "end", tags=(rule["id"], tag),
                             values=(
                                 rule.get("priority", ""),
                                 rule.get("src_ip", "ANY"),
                                 rule.get("dest_port", "ANY"),
                                 rule.get("protocol", "ANY"),
                                 rule.get("direction", "ANY"),
                                 rule.get("action", ""),
                                 rule.get("description", ""),
                             ))

    def _clear_form(self):
        for attr in ("e_priority", "e_src_ip", "e_dest_port", "e_desc"):
            w = getattr(self, attr)
            w.delete(0, "end")
        self.cb_proto.current(0)
        self.cb_dir.current(0)
        self.cb_action.current(0)

    # ────────────────────────────────────────
    # Packet simulation
    # ────────────────────────────────────────
    def _simulate_packet(self):
        packet = {
            "src_ip":    self.p_src_ip.get().strip()    or "0.0.0.0",
            "dest_ip":   self.p_dest_ip.get().strip()   or "0.0.0.0",
            "src_port":  self.p_src_port.get().strip()  or "0",
            "dest_port": self.p_dest_port.get().strip() or "0",
            "protocol":  self.p_proto.get(),
            "direction": self.p_dir.get(),
        }
        verdict = self.engine.evaluate(packet)
        action  = verdict["action"]

        if action == "ALLOW":
            symbol = "✅  ALLOWED"
            color  = GREEN
        else:
            symbol = "❌  BLOCKED"
            color  = RED

        self.verdict_var.set(symbol)
        self.verdict_lbl.configure(fg=color)
        self.match_var.set(f"Matched: {verdict['matched_rule']}   |   {verdict['timestamp']}")
        self._refresh_log()

    # ────────────────────────────────────────
    # Log
    # ────────────────────────────────────────
    def _refresh_log(self):
        entries = self.engine.get_log_entries(300)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        for line in entries:
            tag = "ALLOW" if " ALLOW " in line else "BLOCK" if " BLOCK " in line else "DIM"
            self.log_text.insert("end", line, tag)
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _clear_log(self):
        if messagebox.askyesno("Clear Log", "Erase all log entries?"):
            self.engine.clear_log()
            self._refresh_log()


# ────────────────────────────────────────────
if __name__ == "__main__":
    app = FirewallApp()
    app.mainloop()
