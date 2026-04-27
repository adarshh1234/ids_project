"""
attack_simulator.py  (FIXED)
=============================
Fix: DoSSimulator TARGET_IP was hardcoded to '10.122.67.114' (your LAN IP).
This caused a mismatch — capture.py on localhost never saw the packets if
run on a different interface. Changed to 127.0.0.1 so the attack loops back
on the same machine capture.py is watching.

Usage:
    python attack_simulator.py dos      # Flood your own port
    python attack_simulator.py probe    # Scan your own ports
    python attack_simulator.py both     # Run both
"""

import socket
import threading
import time
import argparse


# ── DoS Simulator ─────────────────────────────────────────────────────────────

class DoSSimulator:
    """
    Simulates a SYN flood against localhost port 8000.
    capture.py (listening on lo / all interfaces) will detect the flood
    and classify it as DoS.

    FIX: TARGET_IP changed from '10.122.67.114' to '127.0.0.1' so
    packets stay on the loopback interface that capture.py watches.
    """
    TARGET_IP   = '127.0.0.1'   # ← FIXED (was '10.122.67.114')
    TARGET_PORT = 8000
    THREADS     = 50
    DURATION    = 30

    def __init__(self):
        self.running   = False
        self.pkt_count = 0
        self.lock      = threading.Lock()

    def _flood_worker(self):
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((self.TARGET_IP, self.TARGET_PORT))
                s.close()
                with self.lock:
                    self.pkt_count += 1
            except Exception:
                pass

    def run(self):
        print(f"\n🔴 Starting DoS simulation against {self.TARGET_IP}:{self.TARGET_PORT}")
        print(f"   Threads: {self.THREADS} | Duration: {self.DURATION}s")
        print(f"   capture.py should detect this as DoS within 5-10 seconds\n")

        self.running = True
        threads = [threading.Thread(target=self._flood_worker, daemon=True)
                   for _ in range(self.THREADS)]
        for t in threads: t.start()

        start = time.time()
        while time.time() - start < self.DURATION:
            elapsed = int(time.time() - start)
            print(f"\r   ⚡ Packets sent: {self.pkt_count:,} | Elapsed: {elapsed}s/{self.DURATION}s", end='')
            time.sleep(1)

        self.running = False
        print(f"\n\n✅ DoS simulation complete. Sent {self.pkt_count:,} connection attempts.")
        print("   Check Live Monitor for DoS alerts!")


# ── Probe / Port Scan Simulator ───────────────────────────────────────────────

class ProbeSimulator:
    TARGET_IP  = '127.0.0.1'
    PORT_RANGE = range(1, 1025)
    TIMEOUT    = 0.05

    def scan_port(self, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.TIMEOUT)
            result = s.connect_ex((self.TARGET_IP, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def run(self):
        print(f"\n🟣 Starting port scan (Probe) against {self.TARGET_IP}")
        print(f"   Scanning ports 1-1024")
        print(f"   capture.py should detect this as Probe within 5-10 seconds\n")

        open_ports = []
        start      = time.time()

        for i, port in enumerate(self.PORT_RANGE):
            if self.scan_port(port):
                open_ports.append(port)
                print(f"   ✅ Port {port} OPEN")
            if i % 100 == 0:
                print(f"\r   🔍 Scanning port {port}/1024...", end='')

        elapsed = time.time() - start
        print(f"\n\n✅ Scan complete in {elapsed:.1f}s")
        print(f"   Open ports found: {open_ports if open_ports else 'None'}")
        print("   Check Live Monitor for Probe alerts!")


# ── Combined ──────────────────────────────────────────────────────────────────

def run_both():
    print("🚨 Running both DoS and Probe simulations...\n")
    probe_thread = threading.Thread(target=ProbeSimulator().run, daemon=True)
    probe_thread.start()
    time.sleep(2)
    DoSSimulator().run()
    probe_thread.join()


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IDS Attack Simulator (safe — localhost only)')
    parser.add_argument('attack', choices=['dos', 'probe', 'both'],
                        help='Type of attack to simulate')
    args = parser.parse_args()

    print("=" * 55)
    print("  IDSGuard Attack Simulator  [FIXED]")
    print("  ⚠️  Targets localhost only — completely safe")
    print("=" * 55)

    print("\n📋 Prerequisites:")
    print("   1. Django server must be running (python manage.py runserver)")
    print("   2. capture.py must be running:")
    print("      sudo python capture.py --iface lo --api http://localhost:8000")
    print("      (use 'lo' for loopback so it sees localhost traffic)")
    print("   3. Open Live Monitor at http://localhost:3000/live\n")

    input("Press Enter to start simulation...")

    if args.attack == 'dos':
        DoSSimulator().run()
    elif args.attack == 'probe':
        ProbeSimulator().run()
    elif args.attack == 'both':
        run_both()
