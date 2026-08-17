#!/usr/bin/env python3
"""
LinuxWays Security Center — Final Release
Written by Atif Ahmed - Platform Architect
LinuxWays

Transparent Desktop Security HUD
Python 3 / GTK3

Designed for:
    X11 + Openbox
    Arch Linux / CachyOS
    1368x768
    1600x900
    1920x1080

FEATURES
--------
- Transparent desktop HUD
- LinuxWays purple / cyan / green visual theme
- Responsive geometry
- CPU / RAM / SWAP / load / disk / uptime
- Network interfaces
- IPv4 addresses
- RX / TX traffic
- Listening TCP / UDP ports
- Application / PID / user when permitted
- Explicit "restricted" ownership when Linux blocks process inspection
- UFW firewall status without sudo
- SSH authentication failures
- SUID / SGID count
- World-writable sensitive files
- Package update count
- Important systemd services
- Security score
- Background deep scan
- No Conky dependency
- No root / sudo requirement

IMPORTANT
---------
Linux intentionally restricts unprivileged users from inspecting some
root-owned processes and sockets.

Therefore a listening port may legitimately appear as:

    22    TCP    sshd • restricted

This means the port is visible, but Linux does not allow the current
desktop user to inspect the owning root process.

The dashboard deliberately does NOT run GTK as root. This avoids:
- blurry / incorrect desktop scaling
- root-owned GUI configuration
- unnecessary privilege escalation
- password prompts

DEPENDENCIES
------------
Arch Linux:

    sudo pacman -S python-gobject gtk3 python-psutil

RUN
---
    python3 linuxways_security_dashboard_final.py

NO SUDO REQUIRED.

CLOSE
-----
Right-click the dashboard
or press Escape.

AUTHOR
------
Atif Ahmed
Platform Architect
LinuxWays
"""

import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, Gdk, GLib, Pango

try:
    import psutil
except ImportError:
    raise SystemExit(
        "Missing dependency: python-psutil\n\n"
        "Arch Linux:\n"
        "sudo pacman -S python-psutil"
    )

APP_NAME = "LinuxWays Security Center"
VERSION = "Final Release"
FAST_MS = 2000
DEEP_MS = 15000

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
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()
    except (subprocess.SubprocessError, OSError, TimeoutError):
        return ""


def fmt_bytes(value):
    value = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def fmt_rate(value):
    return f"{fmt_bytes(value)}/s"


def fmt_uptime(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    if days:
        return f"{days}d {hours:02d}h"
    return f"{hours}h {minutes:02d}m"


def os_name():
    try:
        data = Path("/etc/os-release").read_text(
            encoding="utf-8", errors="ignore"
        )
        match = re.search(r'^PRETTY_NAME="?([^"\n]+)', data, re.MULTILINE)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "Linux"


def interfaces():
    result = []
    try:
        for name, state in psutil.net_if_stats().items():
            if state.isup:
                result.append(name)
    except Exception:
        pass
    return result


def ipv4_addresses():
    result = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for address in addrs:
                if address.family == socket.AF_INET and not address.address.startswith("127."):
                    result.append((name, address.address))
    except Exception:
        pass
    return result


def listening_ports():
    """Rootless TCP/UDP listening-port scanner using ss and psutil."""
    sockets = {}

    if cmd_exists("ss"):
        output = run_cmd(["ss", "-H", "-lntup"], 6)

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue

            protocol_raw = parts[0].lower()
            if protocol_raw.startswith("tcp"):
                protocol = "TCP"
            elif protocol_raw.startswith("udp"):
                protocol = "UDP"
            else:
                continue

            local_address = parts[4]
            try:
                port = local_address.rsplit(":", 1)[-1].rstrip("]")
            except Exception:
                continue

            if not port.isdigit():
                continue

            application = ""
            pid = ""
            user = ""

            match = re.search(r'users:\(\("([^"]+)"(?:,pid=(\d+))?', line)
            if match:
                application = match.group(1) or ""
                pid = match.group(2) or ""

            if pid:
                try:
                    process = psutil.Process(int(pid))
                    try:
                        application = process.name() or application
                    except Exception:
                        pass
                    try:
                        user = process.username() or ""
                    except psutil.AccessDenied:
                        user = "restricted"
                except psutil.AccessDenied:
                    user = "restricted"
                except (psutil.NoSuchProcess, ValueError):
                    pass
                except Exception:
                    pass

            sockets[(port, protocol)] = {
                "port": port,
                "proto": protocol,
                "app": application,
                "pid": pid,
                "user": user,
            }

    try:
        for connection in psutil.net_connections(kind="inet"):
            if not connection.laddr:
                continue

            if connection.type == socket.SOCK_STREAM:
                if connection.status != psutil.CONN_LISTEN:
                    continue
                protocol = "TCP"
            elif connection.type == socket.SOCK_DGRAM:
                protocol = "UDP"
            else:
                continue

            port = str(connection.laddr.port)
            key = (port, protocol)
            entry = sockets.get(
                key,
                {
                    "port": port,
                    "proto": protocol,
                    "app": "",
                    "pid": "",
                    "user": "",
                },
            )

            if connection.pid:
                entry["pid"] = str(connection.pid)
                try:
                    process = psutil.Process(connection.pid)
                    try:
                        entry["app"] = process.name() or entry["app"]
                    except Exception:
                        pass
                    try:
                        entry["user"] = process.username() or entry["user"]
                    except psutil.AccessDenied:
                        entry["user"] = "restricted"
                except psutil.AccessDenied:
                    entry["user"] = "restricted"
                except psutil.NoSuchProcess:
                    pass
                except Exception:
                    pass

            sockets[key] = entry

    except psutil.AccessDenied:
        pass
    except Exception:
        pass

    result = []
    for entry in sockets.values():
        result.append(
            (
                entry["port"],
                entry["proto"],
                entry["app"] or "restricted",
                entry["pid"],
                entry["user"] or "restricted",
            )
        )

    result.sort(
        key=lambda item: (
            int(item[0]) if item[0].isdigit() else 999999,
            item[1],
        )
    )
    return result[:12]


def firewall_state():
    """Read UFW enablement without invoking sudo."""
    if not cmd_exists("ufw"):
        return "NOT INSTALLED"

    try:
        config = Path("/etc/ufw/ufw.conf")
        if config.exists():
            data = config.read_text(encoding="utf-8", errors="ignore")
            match = re.search(
                r"^\s*ENABLED\s*=\s*(yes|no)\s*$",
                data,
                re.IGNORECASE | re.MULTILINE,
            )
            if match:
                return "ACTIVE" if match.group(1).lower() == "yes" else "INACTIVE"
    except (OSError, PermissionError):
        pass

    return "LIMITED (NO ROOT)"


def failed_logins():
    if cmd_exists("journalctl"):
        output = run_cmd(
            [
                "journalctl",
                "--since",
                "24 hours ago",
                "-q",
                "-g",
                "Failed password|authentication failure",
            ],
            6,
        )
        if output:
            return len(output.splitlines())

    for path in ("/var/log/auth.log", "/var/log/secure"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as log:
                return sum(
                    1
                    for line in log
                    if "Failed password" in line
                    or "authentication failure" in line
                )
        except (OSError, PermissionError):
            pass

    return 0


def suid_sgid_count():
    count = 0
    for root in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        if not os.path.isdir(root):
            continue
        try:
            for base, dirs, files in os.walk(root):
                for filename in files:
                    path = os.path.join(base, filename)
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
                for filename in files:
                    path = os.path.join(base, filename)
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
        output = run_cmd(["checkupdates"], 12)
        return len(output.splitlines()) if output else 0

    if cmd_exists("apt"):
        output = run_cmd(["apt", "list", "--upgradable"], 10)
        return sum("/upgradable" in line for line in output.splitlines())

    return 0


def service_state(service):
    if not cmd_exists("systemctl"):
        return "N/A"
    output = run_cmd(["systemctl", "is-active", service], 2)
    return output.upper() if output else "OFF"


def calculate_score(data):
    score = 100

    if data["failed"] >= 10:
        score -= 15
    elif data["failed"] >= 3:
        score -= 7

    if data["firewall"] in ("NOT INSTALLED", "INACTIVE"):
        score -= 15
    elif data["firewall"] in ("LIMITED (NO ROOT)", "UFW ERROR", "UNKNOWN"):
        score -= 5

    if data["writable"]:
        score -= min(15, data["writable"] * 3)

    if data["updates"] >= 20:
        score -= 15
    elif data["updates"] >= 10:
        score -= 8
    elif data["updates"] >= 5:
        score -= 4

    if data["disk"] >= 95:
        score -= 15
    elif data["disk"] >= 90:
        score -= 8

    return max(0, min(100, score))


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
separator {{
    background-color: rgba(120, 150, 190, 0.18);
}}
"""


class SecurityDashboard:
    def __init__(self):
        self.data = {
            "cpu": 0, "ram": 0, "swap": 0, "disk": 0, "load": 0,
            "uptime": 0, "rx": 0, "tx": 0, "interfaces": [], "ipv4": [],
            "ports": [], "firewall": "UNKNOWN", "failed": 0, "suid": 0,
            "writable": 0, "updates": 0, "processes": 0, "score": 100,
        }

        self.rx_last = None
        self.tx_last = None
        self.time_last = None
        self.deep_scan_running = False

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

        self.fast_update()
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
        geometry = screen.get_monitor_geometry(monitor)
        screen_width = geometry.width
        screen_height = geometry.height

        if screen_width <= 1368 and screen_height <= 768:
            width = 342
            height = min(742, screen_height - 16)
            x = 12
            y = max(8, (screen_height - height) // 2)
        elif screen_width <= 1600 and screen_height <= 900:
            width = 368
            height = min(868, screen_height - 20)
            x = 14
            y = max(8, (screen_height - height) // 2)
        else:
            width = 405
            height = min(1000, screen_height - 36)
            x = 18
            y = max(18, (screen_height - height) // 2)

        self.window.set_default_size(width, height)
        self.window.move(x, y)

    def box(self, css_class="card", margin=8):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_start(margin)
        box.set_margin_end(margin)
        box.set_margin_top(4)
        box.set_margin_bottom(4)
        box.get_style_context().add_class(css_class)
        return box

    def label(self, text="", css_class="value"):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        label.get_style_context().add_class(css_class)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        return label

    def row(self, name, value="", value_class="value"):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        row.set_margin_start(9)
        row.set_margin_end(9)
        row.set_margin_top(1)
        row.set_margin_bottom(1)

        left = self.label(name, "label")
        right = self.label(value, value_class)
        right.set_xalign(1)

        row.pack_start(left, False, False, 0)
        row.pack_end(right, True, True, 0)
        return row, right

    def section(self, title):
        label = self.label(title, "section")
        label.set_margin_start(9)
        label.set_margin_top(5)
        label.set_margin_bottom(2)
        return label

    def build(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        root.set_name("root")
        root.set_margin_start(4)
        root.set_margin_end(4)
        root.set_margin_top(4)
        root.set_margin_bottom(4)
        self.window.add(root)

        header = self.box("card-strong", 5)
        title = self.label("LINUXWAYS SECURITY CENTER", "title")
        title.set_margin_start(10)
        title.set_margin_top(7)
        subtitle = self.label(
            "DEEP SYSTEM • NETWORK • SECURITY MONITOR", "subtitle"
        )
        subtitle.set_margin_start(10)
        self.host = self.label("", "small")
        self.host.set_margin_start(10)
        self.host.set_margin_bottom(7)

        header.pack_start(title, False, False, 0)
        header.pack_start(subtitle, False, False, 0)
        header.pack_start(self.host, False, False, 0)
        root.pack_start(header, False, False, 0)

        score_card = self.box("card-strong", 5)
        self.score_label = self.label("100 / 100", "score")
        self.score_label.set_xalign(0.5)
        self.status = self.label("● SECURITY STATUS: GOOD", "good")
        self.status.set_xalign(0.5)
        score_card.pack_start(self.score_label, False, False, 0)
        score_card.pack_start(self.status, False, False, 0)
        root.pack_start(score_card, False, False, 0)

        card = self.box()
        card.pack_start(self.section("SYSTEM OVERVIEW"), False, False, 0)
        self.sys = {}
        for name, key in (
            ("CPU", "cpu"), ("RAM", "ram"), ("SWAP", "swap"),
            ("LOAD", "load"), ("DISK /", "disk"), ("UPTIME", "uptime"),
        ):
            row, value = self.row(name)
            self.sys[key] = value
            card.pack_start(row, False, False, 0)
        root.pack_start(card, False, False, 0)

        card = self.box()
        card.pack_start(self.section("NETWORK"), False, False, 0)
        self.net = {}
        for name, key in (
            ("INTERFACES", "interfaces"), ("IPv4", "ipv4"),
            ("RX", "rx"), ("TX", "tx"),
        ):
            row, value = self.row(name)
            self.net[key] = value
            card.pack_start(row, False, False, 0)
        root.pack_start(card, False, False, 0)

        card = self.box()
        card.pack_start(
            self.section("LISTENING PORTS • APP / PID / USER"),
            False, False, 0
        )
        self.ports_label = self.label("Scanning...", "value")
        self.ports_label.set_margin_start(9)
        self.ports_label.set_margin_end(9)
        self.ports_label.set_margin_bottom(6)
        self.ports_label.set_line_wrap(True)
        self.ports_label.set_lines(3)
        card.pack_start(self.ports_label, False, False, 0)
        root.pack_start(card, False, False, 0)

        card = self.box()
        card.pack_start(self.section("SECURITY SCAN"), False, False, 0)
        self.sec = {}
        for name, key in (
            ("SSH FAILURES 24H", "failed"),
            ("SUID / SGID", "suid"),
            ("WORLD-WRITABLE", "writable"),
            ("UFW FIREWALL", "firewall"),
            ("UPDATES", "updates"),
            ("PROCESSES", "processes"),
        ):
            row, value = self.row(name)
            self.sec[key] = value
            card.pack_start(row, False, False, 0)
        root.pack_start(card, False, False, 0)

        card = self.box()
        card.pack_start(self.section("IMPORTANT SERVICES"), False, False, 0)
        self.services = {}
        for name, service in (
            ("sshd", "sshd"), ("docker", "docker"),
            ("libvirtd", "libvirtd"), ("k3s", "k3s"),
            ("firewalld", "firewalld"),
            ("NetworkManager", "NetworkManager"),
        ):
            row, value = self.row(name.upper())
            self.services[service] = value
            card.pack_start(row, False, False, 0)
        root.pack_start(card, False, False, 0)

        footer = self.label(
            "Deep scan • right-click / ESC to close • LinuxWays", "small"
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
            network = psutil.net_io_counters()
            now = time.monotonic()

            rx_rate = tx_rate = 0
            if self.rx_last is not None and self.tx_last is not None and self.time_last is not None:
                delta_time = max(0.1, now - self.time_last)
                rx_rate = max(0, (network.bytes_recv - self.rx_last) / delta_time)
                tx_rate = max(0, (network.bytes_sent - self.tx_last) / delta_time)

            self.rx_last = network.bytes_recv
            self.tx_last = network.bytes_sent
            self.time_last = now

            self.data.update({
                "cpu": cpu, "ram": ram, "swap": swap, "disk": disk,
                "load": load, "uptime": uptime, "rx": rx_rate, "tx": tx_rate,
                "interfaces": interfaces(),
                "ipv4": ipv4_addresses(),
                "processes": len(psutil.pids()),
            })
            self.render()
        except Exception:
            pass

        return True

    def deep_update(self):
        if self.deep_scan_running:
            return True

        self.deep_scan_running = True

        def worker():
            try:
                result = {
                    "ports": listening_ports(),
                    "firewall": firewall_state(),
                    "failed": failed_logins(),
                    "suid": suid_sgid_count(),
                    "writable": world_writable_sensitive(),
                    "updates": update_count(),
                }
                self.data.update(result)
                self.data["score"] = calculate_score(self.data)
            except Exception:
                pass
            finally:
                self.deep_scan_running = False
                GLib.idle_add(self.render)

        threading.Thread(target=worker, daemon=True).start()
        return True

    def set_color(self, widget, css_class):
        context = widget.get_style_context()
        for class_name in ("good", "warn", "bad", "cyan"):
            context.remove_class(class_name)
        if css_class in ("good", "warn", "bad", "cyan"):
            context.add_class(css_class)

    def render(self):
        data = self.data

        self.host.set_text(f"{socket.gethostname()}  •  {os_name()}")

        security_score = data["score"]
        self.score_label.set_text(f"{security_score:03d} / 100")

        if security_score >= 85:
            self.set_color(self.score_label, "good")
            self.status.set_text("● SECURITY STATUS: GOOD")
            self.set_color(self.status, "good")
        elif security_score >= 65:
            self.set_color(self.score_label, "warn")
            self.status.set_text("● SECURITY STATUS: WARNING")
            self.set_color(self.status, "warn")
        else:
            self.set_color(self.score_label, "bad")
            self.status.set_text("● SECURITY STATUS: CRITICAL")
            self.set_color(self.status, "bad")

        self.sys["cpu"].set_text(f"{data['cpu']:.1f}%")
        self.sys["ram"].set_text(f"{data['ram']:.1f}%")
        self.sys["swap"].set_text(f"{data['swap']:.1f}%")
        self.sys["load"].set_text(f"{data['load']:.2f}")
        self.sys["disk"].set_text(f"{data['disk']:.1f}%")
        self.sys["uptime"].set_text(fmt_uptime(data["uptime"]))

        self.net["interfaces"].set_text(", ".join(data["interfaces"]) or "NONE")
        self.net["ipv4"].set_text(
            ", ".join(f"{name}:{address}" for name, address in data["ipv4"]) or "NONE"
        )
        self.net["rx"].set_text(fmt_rate(data["rx"]))
        self.net["tx"].set_text(fmt_rate(data["tx"]))

        port_lines = []
        for port, protocol, application, pid, user in data["ports"]:
            owner = f"{application} [{pid}]" if pid else application
            if user == "restricted":
                owner += " • restricted"
            elif user:
                owner += f" • {user}"
            port_lines.append(f"{port:<5} {protocol:<4} {owner}")

        self.ports_label.set_text(
            "\n".join(port_lines) if port_lines else "No listening sockets detected"
        )

        self.sec["failed"].set_text(str(data["failed"]))
        self.sec["suid"].set_text(str(data["suid"]))
        self.sec["writable"].set_text(str(data["writable"]))
        self.sec["firewall"].set_text(data["firewall"])

        if data["firewall"] == "ACTIVE":
            self.set_color(self.sec["firewall"], "good")
        elif "LIMITED" in data["firewall"]:
            self.set_color(self.sec["firewall"], "warn")
        elif data["firewall"] == "INACTIVE":
            self.set_color(self.sec["firewall"], "bad")
        else:
            self.set_color(self.sec["firewall"], "bad")

        self.sec["updates"].set_text(str(data["updates"]))
        self.sec["processes"].set_text(str(data["processes"]))

        for service, widget in self.services.items():
            state = service_state(service)
            widget.set_text(state)

            if state == "ACTIVE":
                self.set_color(widget, "good")
            elif state in ("N/A", "OFF", "INACTIVE", "UNKNOWN"):
                self.set_color(widget, "label")
            else:
                self.set_color(widget, "warn")

        return False


def main():
    SecurityDashboard()
    Gtk.main()


if __name__ == "__main__":
    main()
