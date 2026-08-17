#!/usr/bin/env python3
"""
Written by Atif Ahmed - Platform Architect 
LinuxWays Security Center — Transparent Desktop HUD
Python 3 / GTK3

Designed for X11 + Openbox and resolutions:
    1368x768
    1600x900
    1920x1080

Features:
- Real transparent desktop background
- Vibrant LinuxWays purple/cyan/green security HUD
- Responsive left-side geometry
- CPU/RAM/SWAP/load/disk/uptime
- Interface + IPv4 + RX/TX
- Listening ports -> application -> PID when available
- Firewall state
- SSH failures (24h)
- SUID/SGID count
- World-writable sensitive files
- Package updates
- Important services: sshd/docker/libvirtd/k3s/firewalld
- Security score
- Background deep scan
- No Conky dependency

Arch Linux dependencies:
    sudo pacman -S python-gobject gtk3 python-psutil

Run:
    python3 linuxways_security_dashboard_final.py

Runs as a normal desktop user. No sudo/root access is required.
Some Linux security information may be limited by kernel permissions.

Close:
    Right-click the dashboard or press Escape.

Optional privilege:
    sudo python3 linuxways_security_dashboard.py
"""

import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, Gdk, GLib, Pango

try:
    import psutil
except ImportError:
    raise SystemExit(
        "Missing python-psutil.\n"
        "Arch Linux: sudo pacman -S python-psutil"
    )


APP_NAME = "LinuxWays Security Center"
FAST_MS = 2000
DEEP_MS = 15000

# Vibrant LinuxWays palette
BG = "rgba(4, 8, 18, 0.00)"
PANEL = "rgba(9, 15, 30, 0.42)"
PANEL_STRONG = "rgba(13, 20, 40, 0.58)"
BORDER = "rgba(122, 92, 255, 0.58)"
PURPLE = "#b98cff"
PURPLE2 = "#8b5cf6"
CYAN = "#42e8ff"
GREEN = "#55f28a"
YELLOW = "#ffd166"
RED = "#ff5f78"
TEXT = "#e8f2ff"
MUTED = "#91a4bb"


def cmd_exists(name):
    return shutil.which(name) is not None


def run_cmd(cmd, timeout=4):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
        return p.stdout.strip()
    except Exception:
        return ""


def fmt_bytes(v):
    v = float(v)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024:
            return f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} PB"


def fmt_rate(v):
    return fmt_bytes(v) + "/s"


def fmt_uptime(sec):
    sec = int(sec)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, _ = divmod(sec, 60)
    if d:
        return f"{d}d {h:02d}h"
    return f"{h}h {m:02d}m"


def os_name():
    try:
        data = open("/etc/os-release", encoding="utf-8").read()
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)', data, re.M)
        return m.group(1) if m else "Linux"
    except Exception:
        return "Linux"


def interfaces():
    result = []
    stats = psutil.net_if_stats()
    for name, st in stats.items():
        if st.isup:
            result.append(name)
    return result


def ipv4_addresses():
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                result.append((name, a.address))
    return result


def listening_ports():
    """
    Resolve listening sockets to application/PID/user.

    ss is preferred because Linux can expose socket ownership directly there.
    If normal-user permissions hide ownership, psutil is used as a secondary
    resolver. The dashboard never hides a listening port just because its
    owning process cannot be read.
    """
    rows = {}
    ss_rows = {}

    # Preferred Linux source: ss.
    if cmd_exists("ss"):
        out = run_cmd(["ss", "-H", "-lntup"], 6)

        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue

            proto_raw = parts[0].lower()
            proto = "TCP" if proto_raw.startswith("tcp") else "UDP"
            local = parts[4]
            port = local.rsplit(":", 1)[-1] if ":" in local else "?"

            app = "unknown"
            pid = ""
            user = ""

            # ss format:
            # users:(("sshd",pid=123,fd=3))
            m = re.search(
                r'users:\(\("([^"]+)"(?:,pid=(\d+))?',
                line
            )
            if m:
                app = m.group(1) or "unknown"
                pid = m.group(2) or ""

            if pid:
                try:
                    user = psutil.Process(int(pid)).username() or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            key = (port, proto)
            ss_rows[key] = {
                "port": port,
                "proto": proto,
                "app": app,
                "pid": pid,
                "user": user,
            }

    # psutil secondary source. This is useful when ss gives incomplete data.
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                continue

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            key = (str(conn.laddr.port), proto)
            entry = ss_rows.get(key, {
                "port": str(conn.laddr.port),
                "proto": proto,
                "app": "unknown",
                "pid": "",
                "user": "",
            })

            if conn.pid:
                entry["pid"] = str(conn.pid)
                try:
                    proc = psutil.Process(conn.pid)
                    entry["app"] = proc.name() or entry["app"]
                    try:
                        entry["user"] = proc.username() or entry["user"]
                    except Exception:
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            ss_rows[key] = entry
    except (psutil.AccessDenied, OSError):
        pass

    rows = list(ss_rows.values())
    rows.sort(key=lambda x: int(x["port"]) if x["port"].isdigit() else 999999)

    return [
        (r["port"], r["proto"], r["app"], r["pid"], r["user"])
        for r in rows[:12]
    ]



def firewall_state():
    """
    UFW status without root/sudo.

    UFW's `status` command normally requires root. This dashboard therefore
    never asks for sudo and never launches a password prompt. It reads the
    standard UFW configuration when available. If the configuration cannot
    establish the runtime state, it reports LIMITED instead of falsely
    claiming an error.
    """
    if not cmd_exists("ufw"):
        return "NOT INSTALLED"

    try:
        conf = Path("/etc/ufw/ufw.conf")
        if conf.exists():
            data = conf.read_text(errors="ignore")
            m = re.search(
                r"^\s*ENABLED\s*=\s*(yes|no)\s*$",
                data,
                re.I | re.M,
            )
            if m:
                return "ACTIVE" if m.group(1).lower() == "yes" else "INACTIVE"
    except (OSError, PermissionError):
        pass

    return "LIMITED (NO ROOT)"



def failed_logins():
    if cmd_exists("journalctl"):
        out = run_cmd(
            ["journalctl", "--since", "24 hours ago", "-q",
             "-g", "Failed password|authentication failure"],
            6,
        )
        if out:
            return len(out.splitlines())

    for path in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(path):
            try:
                with open(path, errors="ignore") as f:
                    return sum(
                        1 for x in f
                        if "Failed password" in x
                        or "authentication failure" in x
                    )
            except Exception:
                pass
    return 0


def suid_sgid_count():
    count = 0
    for root in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        if not os.path.isdir(root):
            continue
        try:
            for base, dirs, files in os.walk(root):
                dirs[:] = dirs[:]
                for name in files:
                    path = os.path.join(base, name)
                    try:
                        mode = os.stat(path, follow_symlinks=False).st_mode
                        if mode & 0o4000 or mode & 0o2000:
                            count += 1
                    except (OSError, PermissionError):
                        pass
        except Exception:
            pass
    return count


def world_writable_sensitive():
    count = 0
    for root in ("/etc", "/usr/local/bin", "/usr/local/sbin"):
        if not os.path.isdir(root):
            continue
        try:
            for base, dirs, files in os.walk(root):
                for name in files:
                    path = os.path.join(base, name)
                    try:
                        if os.stat(path, follow_symlinks=False).st_mode & 0o002:
                            count += 1
                    except (OSError, PermissionError):
                        pass
        except Exception:
            pass
    return count


def update_count():
    if cmd_exists("checkupdates"):
        out = run_cmd(["checkupdates"], 12)
        return len(out.splitlines()) if out else 0

    if cmd_exists("apt"):
        out = run_cmd(["apt", "list", "--upgradable"], 10)
        return sum("/upgradable" in x for x in out.splitlines())

    return 0


def service_state(service):
    if not cmd_exists("systemctl"):
        return "N/A"
    out = run_cmd(["systemctl", "is-active", service], 2)
    return out.upper() if out else "OFF"


def score(d):
    s = 100

    if d["failed"] >= 10:
        s -= 15
    elif d["failed"] >= 3:
        s -= 7

    if d["firewall"] in ("NOT INSTALLED", "INACTIVE"):
        s -= 15
    elif d["firewall"] in ("LIMITED (NO ROOT)", "UFW ERROR", "UNKNOWN"):
        s -= 5

    if d["writable"]:
        s -= min(15, d["writable"] * 3)

    if d["updates"] >= 20:
        s -= 15
    elif d["updates"] >= 10:
        s -= 8
    elif d["updates"] >= 5:
        s -= 4

    if d["disk"] >= 95:
        s -= 15
    elif d["disk"] >= 90:
        s -= 8

    return max(0, min(100, s))


CSS = f"""
window {{
    background-color: transparent;
}}

#root {{
    background-color: transparent;
}}

.card {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}

.card-strong {{
    background-color: {PANEL_STRONG};
    border: 1px solid rgba(66, 232, 255, 0.42);
    border-radius: 10px;
}}

.title {{
    color: {TEXT};
    font-size: 16px;
    font-weight: 800;
}}

.subtitle {{
    color: {CYAN};
    font-size: 9px;
    font-weight: 700;
}}

.section {{
    color: {PURPLE};
    font-size: 9px;
    font-weight: 800;
    letter-spacing: 1px;
}}

.label {{
    color: {MUTED};
    font-size: 8px;
}}

.value {{
    color: {TEXT};
    font-size: 8px;
    font-weight: 700;
}}

.good {{
    color: {GREEN};
}}

.warn {{
    color: {YELLOW};
}}

.bad {{
    color: {RED};
}}

.cyan {{
    color: {CYAN};
}}

.score {{
    color: {GREEN};
    font-size: 27px;
    font-weight: 900;
}}

.small {{
    color: {MUTED};
    font-size: 7px;
}}

.progress {{
    min-height: 5px;
}}

.progress trough {{
    background-color: rgba(100, 120, 160, 0.16);
    border-radius: 5px;
}}

.progress progress {{
    background-image: linear-gradient(to right, {PURPLE2}, {CYAN});
    border-radius: 5px;
}}

separator {{
    background-color: rgba(120, 150, 190, 0.18);
}}
"""


class SecurityDashboard:
    def __init__(self):
        self.builder = Gtk.Builder()
        self.data = {
            "cpu": 0, "ram": 0, "swap": 0, "disk": 0, "load": 0,
            "uptime": 0, "rx": 0, "tx": 0,
            "interfaces": [], "ipv4": [], "ports": [],
            "firewall": "UNKNOWN", "failed": 0, "suid": 0,
            "writable": 0, "updates": 0, "processes": 0,
            "score": 100,
        }

        self.rx_last = None
        self.tx_last = None
        self.time_last = None

        self.window = Gtk.Window()
        self.window.set_title(APP_NAME)
        self.window.set_decorated(False)
        self.window.set_resizable(False)
        self.window.set_skip_taskbar_hint(True)
        self.window.set_skip_pager_hint(True)
        self.window.set_type_hint(Gdk.WindowTypeHint.DESKTOP)
        self.window.connect("destroy", Gtk.main_quit)
        self.window.connect("button-press-event", self.mouse)
        self.window.connect("key-press-event", self.key)

        screen = self.window.get_screen()
        visual = screen.get_rgba_visual()
        if visual and screen.is_composited():
            self.window.set_visual(visual)

        self.apply_css()
        self.build()
        self.place()

        psutil.cpu_percent(interval=None)

        GLib.timeout_add(FAST_MS, self.fast_update)
        GLib.timeout_add(DEEP_MS, self.deep_update)

        self.deep_update()
        self.window.show_all()

    def apply_css(self):
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS.encode())
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

    def place(self):
        screen = self.window.get_screen()
        monitor = screen.get_primary_monitor()
        geo = screen.get_monitor_geometry(monitor)
        sw, sh = geo.width, geo.height

        if sw <= 1368 and sh <= 768:
            w, h, x, y = 342, 742, 12, max(8, (sh - 742) // 2)
        elif sw <= 1600 and sh <= 900:
            w, h, x, y = 368, 868, 14, max(8, (sh - 868) // 2)
        else:
            w, h, x, y = 405, min(1000, sh - 36), 18, max(18, (sh - min(1000, sh - 36)) // 2)

        self.window.set_default_size(w, h)
        self.window.move(x, y)

    def box(self, cls="card", margin=8):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        b.set_margin_start(margin)
        b.set_margin_end(margin)
        b.set_margin_top(4)
        b.set_margin_bottom(4)
        b.get_style_context().add_class(cls)
        return b

    def label(self, text="", cls="value"):
        l = Gtk.Label(label=text)
        l.set_xalign(0)
        l.get_style_context().add_class(cls)
        l.set_ellipsize(Pango.EllipsizeMode.END)
        return l

    def row(self, name, value="", value_class="value"):
        h = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        h.set_margin_start(9)
        h.set_margin_end(9)
        h.set_margin_top(1)
        h.set_margin_bottom(1)

        left = self.label(name, "label")
        right = self.label(value, value_class)
        right.set_xalign(1)

        h.pack_start(left, False, False, 0)
        h.pack_end(right, True, True, 0)
        return h, right

    def section(self, title):
        l = self.label(title, "section")
        l.set_margin_start(9)
        l.set_margin_top(5)
        l.set_margin_bottom(2)
        return l

    def build(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        root.set_name("root")
        root.set_margin_start(4)
        root.set_margin_end(4)
        root.set_margin_top(4)
        root.set_margin_bottom(4)
        self.window.add(root)

        # Header
        head = self.box("card-strong", 5)
        title = self.label("LINUXWAYS SECURITY CENTER", "title")
        title.set_margin_start(10)
        title.set_margin_top(7)

        sub = self.label("DEEP SYSTEM • NETWORK • SECURITY MONITOR", "subtitle")
        sub.set_margin_start(10)

        self.host = self.label("", "small")
        self.host.set_margin_start(10)
        self.host.set_margin_bottom(7)

        head.pack_start(title, False, False, 0)
        head.pack_start(sub, False, False, 0)
        head.pack_start(self.host, False, False, 0)
        root.pack_start(head, False, False, 0)

        # Score
        score_card = self.box("card-strong", 5)
        self.score_label = self.label("100 / 100", "score")
        self.score_label.set_xalign(0.5)
        self.status = self.label("● SECURITY STATUS: GOOD", "good")
        self.status.set_xalign(0.5)
        score_card.pack_start(self.score_label, False, False, 0)
        score_card.pack_start(self.status, False, False, 0)
        root.pack_start(score_card, False, False, 0)

        # System
        card = self.box()
        card.pack_start(self.section("SYSTEM OVERVIEW"), False, False, 0)
        self.sys = {}
        for n, k in [
            ("CPU", "cpu"), ("RAM", "ram"), ("SWAP", "swap"),
            ("LOAD", "load"), ("DISK /", "disk"), ("UPTIME", "uptime")
        ]:
            r, v = self.row(n)
            self.sys[k] = v
            card.pack_start(r, False, False, 0)
        root.pack_start(card, False, False, 0)

        # Network
        card = self.box()
        card.pack_start(self.section("NETWORK"), False, False, 0)
        self.net = {}
        for n, k in [
            ("INTERFACES", "interfaces"), ("IPv4", "ipv4"),
            ("RX", "rx"), ("TX", "tx")
        ]:
            r, v = self.row(n)
            self.net[k] = v
            card.pack_start(r, False, False, 0)
        root.pack_start(card, False, False, 0)

        # Ports
        card = self.box()
        card.pack_start(self.section("LISTENING PORTS • APP / PID / USER"), False, False, 0)
        self.ports_label = self.label("Scanning...", "value")
        self.ports_label.set_margin_start(9)
        self.ports_label.set_margin_end(9)
        self.ports_label.set_margin_bottom(6)
        self.ports_label.set_line_wrap(True)
        self.ports_label.set_lines(3)
        card.pack_start(self.ports_label, False, False, 0)
        root.pack_start(card, False, False, 0)

        # Security
        card = self.box()
        card.pack_start(self.section("SECURITY SCAN"), False, False, 0)
        self.sec = {}
        for n, k in [
            ("SSH FAILURES 24H", "failed"),
            ("SUID / SGID", "suid"),
            ("WORLD-WRITABLE", "writable"),
            ("UFW FIREWALL", "firewall"),
            ("UPDATES", "updates"),
            ("PROCESSES", "processes")
        ]:
            r, v = self.row(n)
            self.sec[k] = v
            card.pack_start(r, False, False, 0)
        root.pack_start(card, False, False, 0)

        # Services
        card = self.box()
        card.pack_start(self.section("IMPORTANT SERVICES"), False, False, 0)
        self.services = {}
        for n, service in [
            ("sshd", "sshd"),
            ("docker", "docker"),
            ("libvirtd", "libvirtd"),
            ("k3s", "k3s"),
            ("firewalld", "firewalld"),
            ("NetworkManager", "NetworkManager"),
        ]:
            r, v = self.row(n.upper())
            self.services[service] = v
            card.pack_start(r, False, False, 0)
        root.pack_start(card, False, False, 0)

        footer = self.label(
            "Deep scan • right-click / ESC to close • LinuxWays",
            "small"
        )
        footer.set_xalign(0.5)
        footer.set_margin_top(3)
        footer.set_margin_bottom(2)
        root.pack_end(footer, False, False, 0)

    def mouse(self, widget, event):
        if event.button == 3:
            Gtk.main_quit()
        return False

    def key(self, widget, event):
        if event.keyval == Gdk.KEY_Escape:
            Gtk.main_quit()
        return False

    def fast_update(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            swap = psutil.swap_memory().percent
            disk = psutil.disk_usage("/").percent
            load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0
            uptime = time.time() - psutil.boot_time()

            net = psutil.net_io_counters()
            now = time.monotonic()

            rx_rate = tx_rate = 0
            if self.rx_last is not None and self.time_last is not None:
                dt = max(0.1, now - self.time_last)
                rx_rate = max(0, (net.bytes_recv - self.rx_last) / dt)
                tx_rate = max(0, (net.bytes_sent - self.tx_last) / dt)

            self.rx_last = net.bytes_recv
            self.tx_last = net.bytes_sent
            self.time_last = now

            self.data.update({
                "cpu": cpu, "ram": ram, "swap": swap, "disk": disk,
                "load": load, "uptime": uptime,
                "rx": rx_rate, "tx": tx_rate,
                "interfaces": interfaces(),
                "ipv4": ipv4_addresses(),
                "processes": len(psutil.pids()),
            })
            self.render()

        except Exception:
            pass

        return True

    def deep_update(self):
        def worker():
            result = {
                "ports": listening_ports(),
                "firewall": firewall_state(),
                "failed": failed_logins(),
                "suid": suid_sgid_count(),
                "writable": world_writable_sensitive(),
                "updates": update_count(),
            }
            self.data.update(result)
            self.data["score"] = score(self.data)
            GLib.idle_add(self.render)

        threading.Thread(target=worker, daemon=True).start()
        return True

    def set_color(self, widget, cls):
        ctx = widget.get_style_context()
        for c in ("good", "warn", "bad", "cyan"):
            ctx.remove_class(c)
        ctx.add_class(cls)

    def render(self):
        d = self.data

        self.host.set_text(
            f"{socket.gethostname()}  •  {os_name()}"
        )

        sc = d["score"]
        self.score_label.set_text(f"{sc:03d} / 100")

        if sc >= 85:
            self.set_color(self.score_label, "good")
            self.status.set_text("● SECURITY STATUS: GOOD")
            self.set_color(self.status, "good")
        elif sc >= 65:
            self.set_color(self.score_label, "warn")
            self.status.set_text("● SECURITY STATUS: WARNING")
            self.set_color(self.status, "warn")
        else:
            self.set_color(self.score_label, "bad")
            self.status.set_text("● SECURITY STATUS: CRITICAL")
            self.set_color(self.status, "bad")

        self.sys["cpu"].set_text(f"{d['cpu']:.1f}%")
        self.sys["ram"].set_text(f"{d['ram']:.1f}%")
        self.sys["swap"].set_text(f"{d['swap']:.1f}%")
        self.sys["load"].set_text(f"{d['load']:.2f}")
        self.sys["disk"].set_text(f"{d['disk']:.1f}%")
        self.sys["uptime"].set_text(fmt_uptime(d["uptime"]))

        self.net["interfaces"].set_text(", ".join(d["interfaces"]) or "NONE")
        self.net["ipv4"].set_text(
            ", ".join(f"{n}:{ip}" for n, ip in d["ipv4"]) or "NONE"
        )
        self.net["rx"].set_text(fmt_rate(d["rx"]))
        self.net["tx"].set_text(fmt_rate(d["tx"]))

        port_lines = []
        for port, proto, app, pid, user in d["ports"]:
            owner = f"{app}"
            if pid:
                owner += f" [{pid}]"
            if user:
                owner += f" • {user}"
            port_lines.append(f"{port:<5} {proto:<4} {owner}")
        self.ports_label.set_text("\n".join(port_lines) if port_lines else "No listening sockets detected")

        self.sec["failed"].set_text(str(d["failed"]))
        self.sec["suid"].set_text(str(d["suid"]))
        self.sec["writable"].set_text(str(d["writable"]))
        self.sec["firewall"].set_text(d["firewall"])
        self.set_color(
            self.sec["firewall"],
            "good" if d["firewall"] == "ACTIVE" else
            ("warn" if "LIMITED" in d["firewall"] else "bad")
        )
        self.sec["updates"].set_text(str(d["updates"]))
        self.sec["processes"].set_text(str(d["processes"]))

        for service, widget in self.services.items():
            state = service_state(service)
            widget.set_text(state)
            self.set_color(widget, "good" if state == "ACTIVE" else "label")

        return False


def main():
    SecurityDashboard()
    Gtk.main()


if __name__ == "__main__":
    main()
