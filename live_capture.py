"""
live_capture.py
Real-time network packet sniffer that feeds live traffic into the
FirewallEngine for evaluation against the configured rules.

REQUIREMENTS
------------
1. Install scapy:
       pip install scapy

2. Run with elevated privileges (raw sockets require it):
       Linux/macOS :  sudo python gui.py
       Windows     :  Run as Administrator, AND install Npcap
                       (https://npcap.com) with "WinPcap API-compatible
                       mode" checked.

3. This module only EVALUATES and LOGS each live packet against your
   rules (ALLOW/BLOCK verdict) — it is a passive monitor for a lab
   simulator. It does NOT actually drop/redirect real OS traffic.
   That would require integrating with the OS firewall (iptables /
   nftables / WFP) which is out of scope for a teaching tool and
   requires far more careful, host-specific handling.
"""

import threading
import queue
import socket

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_addr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ──────────────────────────────────────────────
# Reverse DNS (hostname) resolution
# ──────────────────────────────────────────────
# Multicast / broadcast style ranges almost never have a useful PTR
# record (they're protocol destinations, not real hosts) — skip the
# lookup for these so we don't waste time waiting on a DNS timeout.
_MULTICAST_PREFIXES = ("224.", "225.", "226.", "227.", "228.", "229.",
                       "230.", "231.", "232.", "233.", "234.", "235.",
                       "236.", "237.", "238.", "239.", "255.255.255.255")

_hostname_cache: dict[str, str] = {}
_hostname_cache_lock = threading.Lock()
_HOSTNAME_LOOKUP_TIMEOUT = 0.5  # seconds


def resolve_hostname(ip: str) -> str:
    """
    Best-effort reverse DNS lookup with caching and a short timeout.
    Returns the IP itself if no PTR record exists or the lookup is
    skipped/times out — never raises, never blocks for long.
    """
    if ip in _hostname_cache:
        return _hostname_cache[ip]

    if ip.startswith(_MULTICAST_PREFIXES) or ip == "0.0.0.0":
        with _hostname_cache_lock:
            _hostname_cache[ip] = ip
        return ip

    result = {"name": ip}

    def _lookup():
        try:
            result["name"] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            result["name"] = ip

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout=_HOSTNAME_LOOKUP_TIMEOUT)

    with _hostname_cache_lock:
        _hostname_cache[ip] = result["name"]
    return result["name"]


class LiveCapture:
    """
    Wraps scapy.sniff() in a background thread and pushes
    (packet_dict, verdict_dict) tuples onto a thread-safe queue
    that the GUI polls on its main loop.
    """

    def __init__(self, engine, iface=None, bpf_filter=None, local_ip=None):
        self.engine = engine
        self.iface = iface or None          # None = scapy default interface
        self.bpf_filter = bpf_filter or "ip"  # restrict to IP traffic by default
        self.local_ip = local_ip or self._detect_local_ip()

        self.result_queue: "queue.Queue" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.running = False

        self.stats = {"total": 0, "allow": 0, "block": 0}

    # ── helpers ──────────────────────────────
    def _detect_local_ip(self):
        if not SCAPY_AVAILABLE:
            return "0.0.0.0"
        try:
            return get_if_addr(conf.iface)
        except Exception:
            return "0.0.0.0"

    @staticmethod
    def list_interfaces():
        if not SCAPY_AVAILABLE:
            return []
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []

    def _direction_of(self, src_ip):
        if src_ip == self.local_ip:
            return "OUTBOUND"
        return "INBOUND"

    def _packet_to_dict(self, pkt):
        if IP not in pkt:
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            src_port = 0
            dst_port = 0
        else:
            proto = "ANY"
            src_port = 0
            dst_port = 0

        return {
            "src_ip": src_ip,
            "dest_ip": dst_ip,
            "src_host": resolve_hostname(src_ip),
            "dest_host": resolve_hostname(dst_ip),
            "src_port": str(src_port),
            "dest_port": str(dst_port),
            "protocol": proto,
            "direction": self._direction_of(src_ip),
        }

    # ── scapy callback (runs on the sniff thread) ──
    def _on_packet(self, pkt):
        if self._stop_event.is_set():
            return
        packet = self._packet_to_dict(pkt)
        if packet is None:
            return
        verdict = self.engine.evaluate(packet)
        self.stats["total"] += 1
        self.stats["allow" if verdict["action"] == "ALLOW" else "block"] += 1
        self.result_queue.put(verdict)

    def _run_sniff(self):
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except PermissionError:
            self.result_queue.put({
                "error": "Permission denied. Run as Administrator/root "
                         "(and install Npcap on Windows)."
            })
        except Exception as e:
            self.result_queue.put({"error": f"Capture error: {e}"})
        finally:
            self.running = False

    # ── public controls ──────────────────────
    def start(self):
        if not SCAPY_AVAILABLE:
            self.result_queue.put({
                "error": "scapy is not installed. Run: pip install scapy"
            })
            return False
        if self.running:
            return False
        self._stop_event.clear()
        self.stats = {"total": 0, "allow": 0, "block": 0}
        self._thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._thread.start()
        self.running = True
        return True

    def stop(self):
        self._stop_event.set()
        self.running = False

    def poll(self, max_items=50):
        """Non-blocking drain of pending results for the GUI to consume."""
        items = []
        for _ in range(max_items):
            try:
                items.append(self.result_queue.get_nowait())
            except queue.Empty:
                break
        return items
