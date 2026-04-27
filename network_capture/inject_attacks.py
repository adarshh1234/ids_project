"""
inject_attacks.py
=================
Bypasses capture.py entirely — posts attack feature vectors directly
to your Django /api/predict/ endpoint so they appear in the dashboard
immediately, without needing Npcap or any packet capture.

Usage:
    python inject_attacks.py dos        # inject 10 DoS alerts
    python inject_attacks.py probe      # inject 10 Probe alerts
    python inject_attacks.py all        # inject DoS + Probe + R2L + U2R
    python inject_attacks.py dos --n 25 # inject 25 DoS alerts

Requirements:
    pip install requests
"""

import requests
import argparse
import time
import random

API = 'http://localhost:8000/api/predict/'  # overridden by --api arg below

# ── Attack templates ──────────────────────────────────────────────────────────

DOS_BASE = {
    'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
    'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
    'land': 0, 'wrong_fragment': 0, 'urgent': 0,
    'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
    'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
    'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
    'num_access_files': 0, 'num_outbound_cmds': 0,
    'is_host_login': 0, 'is_guest_login': 0,
    # High count + 100% serror_rate = Neptune DoS signature
    'count': 511, 'srv_count': 511,
    'serror_rate': 1.0, 'srv_serror_rate': 1.0,
    'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
    'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
    'dst_host_count': 255, 'dst_host_srv_count': 255,
    'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 0.01, 'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 1.0, 'dst_host_srv_serror_rate': 1.0,
    'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
    'source_ip': '10.0.0.5', 'destination_ip': '192.168.1.10',
}

PROBE_BASE = {
    'duration': 0, 'protocol_type': 'tcp', 'service': 'finger',
    'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
    'land': 0, 'wrong_fragment': 0, 'urgent': 0,
    'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
    'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
    'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
    'num_access_files': 0, 'num_outbound_cmds': 0,
    'is_host_login': 0, 'is_guest_login': 0,
    # High diff_srv_rate + rerror_rate = Portsweep signature
    'count': 1, 'srv_count': 1,
    'serror_rate': 0.0, 'srv_serror_rate': 0.0,
    'rerror_rate': 1.0, 'srv_rerror_rate': 1.0,
    'same_srv_rate': 0.02, 'diff_srv_rate': 0.98, 'srv_diff_host_rate': 1.0,
    'dst_host_count': 255, 'dst_host_srv_count': 4,
    'dst_host_same_srv_rate': 0.02, 'dst_host_diff_srv_rate': 0.98,
    'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 1.0,
    'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate': 0.5, 'dst_host_srv_rerror_rate': 1.0,
    'source_ip': '10.10.10.2', 'destination_ip': '192.168.0.50',
}

R2L_BASE = {
    'duration': 299, 'protocol_type': 'tcp', 'service': 'ftp',
    'flag': 'SF', 'src_bytes': 1512, 'dst_bytes': 2368,
    'land': 0, 'wrong_fragment': 0, 'urgent': 0,
    'hot': 2, 'num_failed_logins': 9, 'logged_in': 0,
    'num_compromised': 3, 'root_shell': 0, 'su_attempted': 0,
    'num_root': 0, 'num_file_creations': 2, 'num_shells': 0,
    'num_access_files': 2, 'num_outbound_cmds': 0,
    'is_host_login': 0, 'is_guest_login': 1,
    'count': 2, 'srv_count': 2,
    'serror_rate': 0.0, 'srv_serror_rate': 0.0,
    'rerror_rate': 1.0, 'srv_rerror_rate': 1.0,
    'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
    'dst_host_count': 2, 'dst_host_srv_count': 2,
    'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate': 1.0, 'dst_host_srv_rerror_rate': 1.0,
    'source_ip': '192.168.5.10', 'destination_ip': '192.168.1.20',
}

U2R_BASE = {
    'duration': 0, 'protocol_type': 'tcp', 'service': 'telnet',
    'flag': 'SF', 'src_bytes': 1274, 'dst_bytes': 1837,
    'land': 0, 'wrong_fragment': 0, 'urgent': 0,
    'hot': 4, 'num_failed_logins': 0, 'logged_in': 1,
    'num_compromised': 1, 'root_shell': 1, 'su_attempted': 1,
    'num_root': 1, 'num_file_creations': 0, 'num_shells': 2,
    'num_access_files': 1, 'num_outbound_cmds': 0,
    'is_host_login': 0, 'is_guest_login': 0,
    'count': 1, 'srv_count': 1,
    'serror_rate': 0.0, 'srv_serror_rate': 0.0,
    'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
    'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
    'dst_host_count': 1, 'dst_host_srv_count': 1,
    'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 1.0, 'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
    'source_ip': '192.168.10.5', 'destination_ip': '192.168.1.1',
}

ATTACK_MAP = {
    'dos':   ('DoS  (Neptune)',   DOS_BASE),
    'probe': ('Probe (Portsweep)', PROBE_BASE),
    'r2l':   ('R2L  (FTP brute)', R2L_BASE),
    'u2r':   ('U2R  (Buffer overflow)', U2R_BASE),
}

# ── Injector ──────────────────────────────────────────────────────────────────

def randomise_ips(base: dict) -> dict:
    """Give each alert a slightly different source IP to look realistic."""
    d = base.copy()
    last_octet = random.randint(1, 254)
    d['source_ip'] = f"10.{random.randint(0,9)}.{random.randint(0,9)}.{last_octet}"
    return d


def inject(attack_type: str, n: int):
    label, base = ATTACK_MAP[attack_type]
    print(f"\n🔴 Injecting {n} × {label} alerts → {API}")
    ok = fail = 0

    for i in range(1, n + 1):
        payload = randomise_ips(base)
        try:
            resp = requests.post(API, json=payload, timeout=5)
            if resp.status_code == 201:
                result = resp.json()
                pred   = result.get('prediction', '?')
                conf   = result.get('confidence', 0)
                sev    = result.get('severity', '?')
                blk    = result.get('blockchain', {}).get('block_number', '?')
                ok    += 1
                print(f"  [{i:>3}/{n}] ✅ {pred:8s} | {conf}% | {sev:8s} | block #{blk}")
            else:
                fail += 1
                print(f"  [{i:>3}/{n}] ❌ HTTP {resp.status_code}: {resp.text[:120]}")
        except requests.exceptions.ConnectionError:
            fail += 1
            print(f"  [{i:>3}/{n}] ❌ Cannot reach {API} — is Django running?")
            break
        except Exception as e:
            fail += 1
            print(f"  [{i:>3}/{n}] ❌ Error: {e}")

        time.sleep(0.3)   # small delay so timestamps spread out in the feed

    print(f"\n  Done: {ok} injected, {fail} failed.")
    return ok


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IDS Direct Attack Injector')
    parser.add_argument('attack', choices=['dos', 'probe', 'r2l', 'u2r', 'all'],
                        help='Attack type to inject')
    parser.add_argument('--n', type=int, default=10,
                        help='Number of alerts to inject (default: 10)')
    parser.add_argument('--api', default='http://localhost:8000',
                        help='Django base URL (default: http://localhost:8000)')
    args = parser.parse_args()

    API = args.api.rstrip('/') + '/api/predict/'

    print("=" * 55)
    print("  IDSGuard Direct Attack Injector")
    print("  Bypasses capture.py — posts directly to Django API")
    print("=" * 55)
    print(f"  API endpoint : {API}")
    print(f"  Attack type  : {args.attack}")
    print(f"  Count        : {args.n}")
    print("=" * 55)

    types = ['dos', 'probe', 'r2l', 'u2r'] if args.attack == 'all' else [args.attack]
    total = 0
    for t in types:
        total += inject(t, args.n)

    print(f"\n🎯 Total alerts injected: {total}")
    print("   Refresh your dashboard — you should see the new alerts now!")
    print("   Live Monitor auto-refreshes every 3s.")
    