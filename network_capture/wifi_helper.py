"""
wifi_helper.py
==============
Detect WiFi / Ethernet interfaces and help capture normal baseline traffic.

Usage:
    python wifi_helper.py --list
    python wifi_helper.py --detect
    python wifi_helper.py --capture-normal --duration 60
    python wifi_helper.py --capture-normal --iface "Wi-Fi" --api http://localhost:8000
"""

import argparse
import platform
import subprocess
import sys
import time


def list_interfaces():
    try:
        from scapy.all import get_if_list, get_if_addr
        interfaces = []
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
            except Exception:
                addr = 'unknown'
            interfaces.append({'name': iface, 'ip': addr})
        return interfaces
    except ImportError:
        print("Scapy not installed. Run: pip install scapy")
        return []


def detect_wifi_interface():
    """Pick the best interface for capturing real (normal) WiFi traffic."""
    interfaces = list_interfaces()
    if not interfaces:
        return None, []

    system = platform.system()
    wifi_keywords = ['wi-fi', 'wifi', 'wlan', 'wireless', 'en0', 'eth', 'ethernet']
    scored = []

    for iface in interfaces:
        name = iface['name'].lower()
        score = 0
        if iface['ip'] not in ('0.0.0.0', 'unknown', '127.0.0.1'):
            score += 10
        for kw in wifi_keywords:
            if kw in name:
                score += 5
        if system == 'Windows' and 'wi-fi' in name:
            score += 20
        if system == 'Darwin' and name.startswith('en'):
            score += 15
        if 'loopback' in name or 'lo' in name:
            score -= 50
        scored.append((score, iface))

    scored.sort(key=lambda x: x[0], reverse=True)
    best = scored[0][1] if scored and scored[0][0] > 0 else None
    return best, [i[1] for i in scored]


def capture_normal_traffic(iface, api_url, duration, bpf_filter='ip'):
    """Capture live traffic for a set duration — mostly normal WiFi activity."""
    print(f"\nCapturing NORMAL traffic on '{iface}' for {duration}s")
    print("  Browse the web, stream video, or use apps to generate realistic traffic.")
    print("  Press Ctrl+C to stop early.\n")

    from capture import FlowManager, SubmitterThread
    from scapy.all import sniff

    manager = FlowManager(api_url=api_url)
    submitter = SubmitterThread(manager, interval=5)
    submitter.start()

    start = time.time()
    try:
        while time.time() - start < duration:
            sniff(iface=iface, filter=bpf_filter, prn=manager.process_packet,
                  store=False, timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        manager.submit_completed()
        manager.print_stats()
        normal = manager.stats['predictions_sent'] - manager.stats['attacks_detected']
        print(f"\n  Summary: {manager.stats['predictions_sent']} flows analyzed")
        print(f"           {normal} classified as normal")
        print(f"           {manager.stats['attacks_detected']} flagged as attacks")


def windows_netsh_wifi():
    """Show connected WiFi SSID on Windows."""
    if platform.system() != 'Windows':
        return None
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if 'SSID' in line and 'BSSID' not in line:
                return line.split(':', 1)[-1].strip()
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description='WiFi interface helper for IDSGuard')
    parser.add_argument('--list', action='store_true', help='List all interfaces')
    parser.add_argument('--detect', action='store_true', help='Auto-detect best WiFi interface')
    parser.add_argument('--capture-normal', action='store_true',
                        help='Capture normal traffic for baseline testing')
    parser.add_argument('--iface', default=None, help='Network interface name')
    parser.add_argument('--api', default='http://localhost:8000', help='Django API URL')
    parser.add_argument('--duration', type=int, default=60, help='Capture duration (seconds)')
    parser.add_argument('--filter', default='ip', help='BPF filter')
    args = parser.parse_args()

    if args.list or (not args.detect and not args.capture_normal):
        print("\nAvailable network interfaces:")
        print("-" * 50)
        for iface in list_interfaces():
            marker = ""
            if iface['ip'] not in ('0.0.0.0', 'unknown', '127.0.0.1'):
                marker = " ← active"
            print(f"  {iface['name']:30s} {iface['ip']}{marker}")
        ssid = windows_netsh_wifi()
        if ssid:
            print(f"\n  Connected WiFi: {ssid}")
        print("\nRun with --detect to pick the best interface automatically.")
        return

    if args.detect:
        best, all_ifaces = detect_wifi_interface()
        print("\nInterface ranking (best first):")
        for i, iface in enumerate(all_ifaces[:5]):
            print(f"  {i+1}. {iface['name']} ({iface['ip']})")
        if best:
            print(f"\n  Recommended: {best['name']}")
            print(f"  Capture command:")
            print(f"    python capture.py --iface \"{best['name']}\" --api {args.api}")
        else:
            print("\n  No suitable interface found. Run as Administrator.")
        return

    if args.capture_normal:
        iface = args.iface
        if not iface:
            best, _ = detect_wifi_interface()
            if not best:
                print("Could not detect interface. Use --iface explicitly.")
                sys.exit(1)
            iface = best['name']
            print(f"Auto-selected interface: {iface}")
        capture_normal_traffic(iface, args.api, args.duration, args.filter)


if __name__ == '__main__':
    main()
