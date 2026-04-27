"""
network_capture/capture.py  (FIXED)
=====================================
Fix: submit_completed() was clearing self.completed_flows BEFORE passing
the list to flow.finalise(), so serror_rate and all DoS pattern features
were always computed against an empty window. The fix passes a snapshot
to finalise() while keeping completed_flows intact for stats, then clears.

Run with root/admin privileges:
    sudo python capture.py --iface eth0 --api http://localhost:8000
"""

import time
import threading
import argparse
import requests
import logging
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not installed. Run: pip install scapy")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('IDS-Capture')


# ── TCP Flag mapping ──────────────────────────────────────────────────────────
def get_tcp_flag(flags):
    if not flags:
        return 'OTH'
    f = int(flags)
    SYN = bool(f & 0x02)
    ACK = bool(f & 0x10)
    FIN = bool(f & 0x01)
    RST = bool(f & 0x04)

    if SYN and not ACK:  return 'S0'
    if SYN and ACK:      return 'SF'
    if RST and SYN:      return 'RSTO'
    if RST:              return 'REJ'
    if FIN and ACK:      return 'SF'
    if FIN:              return 'SH'
    return 'OTH'


# ── Port → Service mapping ────────────────────────────────────────────────────
PORT_SERVICE = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
    25: 'smtp', 53: 'domain_u', 67: 'urp_i', 68: 'urp_i',
    69: 'tftp_u', 79: 'finger', 80: 'http', 110: 'pop_3',
    111: 'sunrpc', 113: 'auth', 119: 'nntp', 123: 'ntp_u',
    135: 'loc_srv', 137: 'netbios_ns', 138: 'netbios_dgm',
    139: 'netbios_ssn', 143: 'imap4', 161: 'snmp', 194: 'IRC',
    389: 'ldap', 443: 'http_443', 445: 'microsoft_ds',
    512: 'exec', 513: 'login', 514: 'shell', 515: 'printer',
    520: 'efs', 540: 'uucp', 543: 'klogin', 544: 'kshell',
    587: 'smtp', 993: 'imap4', 995: 'pop_3',
    1080: 'other', 3306: 'other', 3389: 'other',
    5432: 'other', 6667: 'IRC', 8080: 'http', 8000: 'http',
}

def port_to_service(port, proto):
    if proto == 'icmp':
        return 'eco_i'
    return PORT_SERVICE.get(port, 'other')


# ── Flow key ──────────────────────────────────────────────────────────────────
class FlowKey:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto    = proto

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.proto == other.proto)


# ── Flow record ───────────────────────────────────────────────────────────────
class FlowRecord:
    TIMEOUT       = 15
    MAX_PACKETS   = 20
    MAX_SYN_COUNT = 10

    def __init__(self, key: 'FlowKey', timestamp: float):
        self.key       = key
        self.start_ts  = timestamp
        self.last_ts   = timestamp
        self.packets   = []

        self.src_bytes  = 0
        self.dst_bytes  = 0
        self.syn_count  = 0
        self.rej_count  = 0
        self.wrong_frag = 0
        self.urgent     = 0
        self.land       = 0
        self.flags_seen = set()
        self.last_flag  = 'OTH'

    def add_packet(self, pkt, size: int, flags: str, is_reverse: bool):
        now = time.time()
        self.last_ts = now
        self.packets.append((now, size, flags, is_reverse))
        if is_reverse:
            self.dst_bytes += size
        else:
            self.src_bytes += size
            self.flags_seen.add(flags)
            self.last_flag = flags
            if flags == 'S0':  self.syn_count += 1
            if flags == 'REJ': self.rej_count += 1
        if hasattr(pkt, 'TCP') and pkt['TCP'].urgptr:
            self.urgent += 1

    @property
    def duration(self):
        return self.last_ts - self.start_ts

    @property
    def is_expired(self):
        return (time.time() - self.last_ts) > self.TIMEOUT

    @property
    def should_force_close(self):
        return self.syn_count >= self.MAX_SYN_COUNT or len(self.packets) >= self.MAX_PACKETS

    def finalise(self, recent_flows: list) -> dict:
        proto   = self.key.proto
        service = port_to_service(self.key.dst_port, proto)
        flag    = self.last_flag

        now       = time.time()
        window    = [f for f in recent_flows if (now - f.last_ts) <= 2.0]
        same_host = [f for f in window if f.key.dst_ip == self.key.dst_ip]
        same_srv  = [f for f in window if port_to_service(f.key.dst_port, f.key.proto) == service]

        count     = max(len(same_host), 1)
        srv_count = max(len(same_srv),  1)

        serror_rate     = sum(1 for f in same_host if f.syn_count > 0) / count
        srv_serror_rate = sum(1 for f in same_srv  if f.syn_count > 0) / srv_count
        rerror_rate     = sum(1 for f in same_host if f.rej_count > 0) / count
        srv_rerror_rate = sum(1 for f in same_srv  if f.rej_count > 0) / srv_count

        same_srv_rate = sum(
            1 for f in same_host
            if port_to_service(f.key.dst_port, f.key.proto) == service
        ) / count
        diff_srv_rate = 1.0 - same_srv_rate

        dst_host_flows = [
            f for f in recent_flows if f.key.dst_ip == self.key.dst_ip
        ][-100:]
        dhc = max(len(dst_host_flows), 1)
        dst_host_srv = [
            f for f in dst_host_flows
            if port_to_service(f.key.dst_port, f.key.proto) == service
        ]
        dhsc = max(len(dst_host_srv), 1)

        dst_host_same_srv_rate      = dhsc / dhc
        dst_host_diff_srv_rate      = 1.0 - dst_host_same_srv_rate
        dst_host_same_src_port_rate = sum(
            1 for f in dst_host_flows if f.key.src_port == self.key.src_port
        ) / dhc
        dst_host_srv_diff_host_rate = sum(
            1 for f in dst_host_srv if f.key.src_ip != self.key.src_ip
        ) / dhsc
        dst_host_serror_rate     = sum(1 for f in dst_host_flows if f.syn_count > 0) / dhc
        dst_host_srv_serror_rate = sum(1 for f in dst_host_srv  if f.syn_count > 0) / dhsc
        dst_host_rerror_rate     = sum(1 for f in dst_host_flows if f.rej_count > 0) / dhc
        dst_host_srv_rerror_rate = sum(1 for f in dst_host_srv  if f.rej_count > 0) / dhsc

        return {
            'duration':           int(self.duration),
            'protocol_type':      proto,
            'service':            service,
            'flag':               flag,
            'src_bytes':          self.src_bytes,
            'dst_bytes':          self.dst_bytes,
            'land':               1 if self.key.src_ip == self.key.dst_ip else 0,
            'wrong_fragment':     self.wrong_frag,
            'urgent':             self.urgent,
            'hot':                0,
            'num_failed_logins':  0,
            'logged_in':          1 if flag == 'SF' else 0,
            'num_compromised':    0,
            'root_shell':         0,
            'su_attempted':       0,
            'num_root':           0,
            'num_file_creations': 0,
            'num_shells':         0,
            'num_access_files':   0,
            'num_outbound_cmds':  0,
            'is_host_login':      0,
            'is_guest_login':     0,
            'count':              count,
            'srv_count':          srv_count,
            'serror_rate':        round(serror_rate, 2),
            'srv_serror_rate':    round(srv_serror_rate, 2),
            'rerror_rate':        round(rerror_rate, 2),
            'srv_rerror_rate':    round(srv_rerror_rate, 2),
            'same_srv_rate':      round(same_srv_rate, 2),
            'diff_srv_rate':      round(diff_srv_rate, 2),
            'srv_diff_host_rate': 0.0,
            'dst_host_count':               min(dhc, 255),
            'dst_host_srv_count':           min(dhsc, 255),
            'dst_host_same_srv_rate':       round(dst_host_same_srv_rate, 2),
            'dst_host_diff_srv_rate':       round(dst_host_diff_srv_rate, 2),
            'dst_host_same_src_port_rate':  round(dst_host_same_src_port_rate, 2),
            'dst_host_srv_diff_host_rate':  round(dst_host_srv_diff_host_rate, 2),
            'dst_host_serror_rate':         round(dst_host_serror_rate, 2),
            'dst_host_srv_serror_rate':     round(dst_host_srv_serror_rate, 2),
            'dst_host_rerror_rate':         round(dst_host_rerror_rate, 2),
            'dst_host_srv_rerror_rate':     round(dst_host_srv_rerror_rate, 2),
            'source_ip':      self.key.src_ip,
            'destination_ip': self.key.dst_ip,
        }


# ── Flow Manager ──────────────────────────────────────────────────────────────
class FlowManager:
    def __init__(self, api_url: str, submit_interval: int = 5):
        self.api_url         = api_url.rstrip('/') + '/api/predict/'
        self.submit_interval = submit_interval
        self.active_flows    = {}
        self.completed_flows = []
        self.lock            = threading.Lock()
        self.stats = {
            'packets_seen':     0,
            'flows_completed':  0,
            'predictions_sent': 0,
            'attacks_detected': 0,
        }

    def process_packet(self, pkt):
        if not pkt.haslayer('IP'):
            return

        ip         = pkt['IP']
        proto_name = 'icmp'
        src_port = dst_port = 0
        flags    = 'OTH'

        if pkt.haslayer('TCP'):
            tcp        = pkt['TCP']
            proto_name = 'tcp'
            src_port   = tcp.sport
            dst_port   = tcp.dport
            flags      = get_tcp_flag(tcp.flags)
        elif pkt.haslayer('UDP'):
            udp        = pkt['UDP']
            proto_name = 'udp'
            src_port   = udp.sport
            dst_port   = udp.dport
            flags      = 'SF'
        elif pkt.haslayer('ICMP'):
            proto_name = 'icmp'

        with self.lock:
            self.stats['packets_seen'] += 1
            key     = FlowKey(ip.src, ip.dst, src_port, dst_port, proto_name)
            rev_key = FlowKey(ip.dst, ip.src, dst_port, src_port, proto_name)

            if rev_key in self.active_flows:
                flow     = self.active_flows[rev_key]
                flow_key = rev_key
                flow.add_packet(pkt, len(pkt), flags, is_reverse=True)
            else:
                if key not in self.active_flows:
                    self.active_flows[key] = FlowRecord(key, time.time())
                flow     = self.active_flows[key]
                flow_key = key
                flow.add_packet(pkt, len(pkt), flags, is_reverse=False)

            if flags in ('REJ', 'RSTO') or (proto_name == 'tcp' and flags == 'SF'):
                self._close_flow(flow_key)
            elif flow_key in self.active_flows and self.active_flows[flow_key].should_force_close:
                log.warning(
                    f"⚡ Flood detected from {ip.src} → {ip.dst}:{dst_port} "
                    f"(SYNs={flow.syn_count}, pkts={len(flow.packets)}) — closing flow"
                )
                self._close_flow(flow_key)

            expired = [k for k, v in self.active_flows.items() if v.is_expired]
            for k in expired:
                self._close_flow(k)

    def _close_flow(self, key: FlowKey):
        if key not in self.active_flows:
            return
        flow = self.active_flows.pop(key)
        self.completed_flows.append(flow)
        self.stats['flows_completed'] += 1
        if len(self.completed_flows) > 200:
            self.completed_flows = self.completed_flows[-200:]

    def submit_completed(self):
        """
        Submit completed flows to Django API.

        FIX: Previously self.completed_flows was cleared BEFORE finalise()
        was called, so all time-window statistics (serror_rate, count, etc.)
        were computed against an empty list — DoS patterns were invisible.

        Now we take a snapshot first, call finalise() against the full
        snapshot so stats are accurate, THEN clear the submitted flows.
        """
        with self.lock:
            # Take a snapshot but do NOT clear yet
            to_submit = self.completed_flows[:]

        submitted_ids = []
        for flow in to_submit:
            try:
                # Pass the full snapshot so window stats are computed correctly
                features = flow.finalise(to_submit)
                resp     = requests.post(self.api_url, json=features, timeout=5)
                if resp.status_code == 201:
                    result = resp.json()
                    self.stats['predictions_sent'] += 1
                    pred = result.get('prediction', 'Unknown')
                    conf = result.get('confidence', 0)
                    sev  = result.get('severity', 'info')
                    if pred != 'Normal':
                        self.stats['attacks_detected'] += 1
                        log.warning(
                            f"🚨 ATTACK [{sev.upper()}] {pred} | "
                            f"{flow.key.src_ip}:{flow.key.src_port} → "
                            f"{flow.key.dst_ip}:{flow.key.dst_port} | "
                            f"Confidence: {conf}% | "
                            f"Block #{result.get('blockchain', {}).get('block_number', '?')}"
                        )
                    else:
                        log.info(
                            f"✅ Normal | "
                            f"{flow.key.src_ip} → {flow.key.dst_ip}:{flow.key.dst_port} | "
                            f"{conf}%"
                        )
                    submitted_ids.append(id(flow))
                else:
                    log.error(f"API returned {resp.status_code}: {resp.text[:200]}")
            except requests.exceptions.ConnectionError:
                log.error("❌ Cannot reach Django API. Is the server running?")
            except Exception as e:
                log.error(f"Submission error: {e}")

        # NOW remove only the successfully submitted flows
        with self.lock:
            self.completed_flows = [
                f for f in self.completed_flows if id(f) not in submitted_ids
            ]

    def print_stats(self):
        s = self.stats
        log.info(
            f"📊 Stats | Packets: {s['packets_seen']} | "
            f"Flows: {s['flows_completed']} | "
            f"Sent: {s['predictions_sent']} | "
            f"Attacks: {s['attacks_detected']}"
        )


# ── Periodic submitter thread ─────────────────────────────────────────────────
class SubmitterThread(threading.Thread):
    def __init__(self, manager: FlowManager, interval: int):
        super().__init__(daemon=True)
        self.manager  = manager
        self.interval = interval

    def run(self):
        while True:
            time.sleep(self.interval)
            self.manager.submit_completed()
            self.manager.print_stats()


# ── Main entry ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='IDS Real-Time Traffic Capture')
    parser.add_argument('--iface',    default=None,
                        help='Network interface (e.g. eth0, en0, Wi-Fi). Default: all')
    parser.add_argument('--api',      default='http://localhost:8000',
                        help='Django API base URL')
    parser.add_argument('--interval', default=5, type=int,
                        help='Seconds between batch submissions (default: 5)')
    parser.add_argument('--filter',   default='ip',
                        help='BPF packet filter (default: "ip")')
    parser.add_argument('--list',     action='store_true',
                        help='List available network interfaces and exit')
    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print("❌ Scapy is required. Install with:  pip install scapy")
        return

    if args.list:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  • {iface}")
        return

    manager   = FlowManager(api_url=args.api, submit_interval=args.interval)
    submitter = SubmitterThread(manager, args.interval)
    submitter.start()

    log.info("=" * 60)
    log.info("  IDSGuard — Real-Time Network Capture  [FIXED]")
    log.info("=" * 60)
    log.info(f"  Interface      : {args.iface or 'ALL'}")
    log.info(f"  API            : {args.api}")
    log.info(f"  Filter         : {args.filter}")
    log.info(f"  Submit every   : {args.interval}s")
    log.info(f"  DoS threshold  : {FlowRecord.MAX_SYN_COUNT} SYNs or {FlowRecord.MAX_PACKETS} packets")
    log.info(f"  Flow timeout   : {FlowRecord.TIMEOUT}s")
    log.info("=" * 60)
    log.info("⚡ Capturing packets... Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=manager.process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        log.info("\n🛑 Capture stopped by user.")
        manager.print_stats()
    except PermissionError:
        log.error("❌ Permission denied. Run as Administrator.")
    except Exception as e:
        log.error(f"Capture error: {e}")


if __name__ == '__main__':
    main()
