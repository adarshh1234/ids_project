"""
novel_attacks.py
================
Feature vectors for attack patterns NOT present in NSL-KDD training data.
Used to validate unknown/zero-day detection via the anomaly detector.
"""

import random


def _base():
    return {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'http',
        'flag': 'SF', 'src_bytes': 0, 'dst_bytes': 0,
        'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
        'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0,
        'is_host_login': 0, 'is_guest_login': 0,
        'count': 1, 'srv_count': 1,
        'serror_rate': 0.0, 'srv_serror_rate': 0.0,
        'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        'dst_host_count': 255, 'dst_host_srv_count': 255,
        'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
    }


def dns_tunnel() -> dict:
    """Simulates DNS tunneling — high UDP domain traffic, unusual byte ratios."""
    d = _base()
    d.update({
        'protocol_type': 'udp', 'service': 'domain_u', 'flag': 'SF',
        'duration': 45, 'src_bytes': 8192, 'dst_bytes': 16384,
        'count': 89, 'srv_count': 89,
        'same_srv_rate': 0.12, 'diff_srv_rate': 0.88,
        'srv_diff_host_rate': 0.95,
        'dst_host_count': 200, 'dst_host_srv_count': 180,
        'dst_host_same_srv_rate': 0.15, 'dst_host_diff_srv_rate': 0.85,
        'dst_host_same_src_port_rate': 0.92,
        'source_ip': '10.99.1.5', 'destination_ip': '8.8.8.8',
    })
    return d


def crypto_mining() -> dict:
    """Simulates cryptominer C2 — persistent high outbound to unusual ports."""
    d = _base()
    d.update({
        'protocol_type': 'tcp', 'service': 'other', 'flag': 'S0',
        'duration': 7200, 'src_bytes': 128, 'dst_bytes': 1048576,
        'logged_in': 0, 'count': 500, 'srv_count': 480,
        'serror_rate': 0.7, 'srv_serror_rate': 0.65,
        'same_srv_rate': 0.05, 'diff_srv_rate': 0.95,
        'srv_diff_host_rate': 0.9,
        'dst_host_count': 255, 'dst_host_srv_count': 240,
        'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.96,
        'dst_host_serror_rate': 0.6,
        'source_ip': '192.168.1.55', 'destination_ip': '45.33.32.156',
    })
    return d


def data_exfiltration() -> dict:
    """Large outbound transfer with minimal inbound — not in NSL-KDD patterns."""
    d = _base()
    d.update({
        'protocol_type': 'tcp', 'service': 'http_443', 'flag': 'S0',
        'duration': 600, 'src_bytes': 256, 'dst_bytes': 2097152,
        'logged_in': 0, 'count': 80, 'srv_count': 75,
        'serror_rate': 0.4, 'srv_serror_rate': 0.35,
        'same_srv_rate': 0.1, 'diff_srv_rate': 0.9,
        'srv_diff_host_rate': 0.85,
        'dst_host_count': 200, 'dst_host_srv_count': 180,
        'num_access_files': 50,
        'dst_host_same_srv_rate': 0.08, 'dst_host_diff_srv_rate': 0.92,
        'source_ip': '192.168.2.10', 'destination_ip': '185.220.101.1',
    })
    return d


def iot_botnet() -> dict:
    """IoT botnet beaconing — many short UDP connections to random hosts."""
    d = _base()
    d.update({
        'protocol_type': 'udp', 'service': 'other', 'flag': 'OTH',
        'duration': 1, 'src_bytes': 64, 'dst_bytes': 0,
        'count': 400, 'srv_count': 12,
        'same_srv_rate': 0.03, 'diff_srv_rate': 0.97,
        'srv_diff_host_rate': 0.99,
        'serror_rate': 0.85, 'srv_serror_rate': 0.6,
        'dst_host_count': 255, 'dst_host_srv_count': 20,
        'dst_host_same_srv_rate': 0.04, 'dst_host_diff_srv_rate': 0.96,
        'dst_host_serror_rate': 0.8,
        'source_ip': '192.168.0.99', 'destination_ip': '203.0.113.50',
    })
    return d


def slowloris_variant() -> dict:
    """Slow HTTP attack variant — long duration, low byte count, many connections."""
    d = _base()
    d.update({
        'protocol_type': 'tcp', 'service': 'http', 'flag': 'S0',
        'duration': 300, 'src_bytes': 1, 'dst_bytes': 0,
        'count': 150, 'srv_count': 150,
        'serror_rate': 0.95, 'srv_serror_rate': 0.95,
        'same_srv_rate': 0.99, 'diff_srv_rate': 0.01,
        'dst_host_count': 255, 'dst_host_srv_count': 255,
        'dst_host_serror_rate': 0.95, 'dst_host_srv_serror_rate': 0.95,
        'dst_host_same_src_port_rate': 0.02,
        'source_ip': '10.50.0.1', 'destination_ip': '192.168.1.80',
    })
    return d


def icmp_flood_variant() -> dict:
    """ICMP flood with unusual rate patterns."""
    d = _base()
    d.update({
        'protocol_type': 'icmp', 'service': 'eco_i', 'flag': 'OTH',
        'duration': 3, 'src_bytes': 0, 'dst_bytes': 0,
        'count': 511, 'srv_count': 511,
        'serror_rate': 0.0, 'rerror_rate': 0.0,
        'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 255, 'dst_host_srv_count': 255,
        'dst_host_same_srv_rate': 1.0,
        'dst_host_serror_rate': 0.0,
        'urgent': 50, 'wrong_fragment': 10,
        'source_ip': '10.0.0.77', 'destination_ip': '192.168.1.1',
    })
    return d


def lateral_movement() -> dict:
    """Internal host scanning + credential reuse pattern."""
    d = _base()
    d.update({
        'protocol_type': 'tcp', 'service': 'ssh', 'flag': 'REJ',
        'duration': 60, 'src_bytes': 200, 'dst_bytes': 0,
        'hot': 5, 'num_failed_logins': 25, 'logged_in': 0,
        'count': 40, 'srv_count': 8,
        'rerror_rate': 0.9, 'srv_rerror_rate': 0.85,
        'same_srv_rate': 0.2, 'diff_srv_rate': 0.8,
        'srv_diff_host_rate': 0.75,
        'dst_host_count': 40, 'dst_host_srv_count': 8,
        'dst_host_rerror_rate': 0.88,
        'source_ip': '192.168.1.50', 'destination_ip': '192.168.1.100',
    })
    return d


def normal_browsing() -> dict:
    """Typical web browsing — should classify as Normal."""
    d = _base()
    d.update({
        'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'duration': 2, 'src_bytes': 300, 'dst_bytes': 4096,
        'logged_in': 0, 'count': 5, 'srv_count': 5,
        'same_srv_rate': 0.8, 'diff_srv_rate': 0.2,
        'dst_host_count': 10, 'dst_host_srv_count': 8,
        'dst_host_same_srv_rate': 0.7,
        'source_ip': '192.168.1.10', 'destination_ip': '93.184.216.34',
    })
    return d


def normal_https() -> dict:
    """Typical HTTPS session."""
    d = _base()
    d.update({
        'protocol_type': 'tcp', 'service': 'http_443', 'flag': 'SF',
        'duration': 8, 'src_bytes': 1200, 'dst_bytes': 45000,
        'logged_in': 0, 'count': 3, 'srv_count': 3,
        'same_srv_rate': 0.9, 'diff_srv_rate': 0.1,
        'dst_host_count': 5, 'dst_host_srv_count': 4,
        'source_ip': '192.168.1.10', 'destination_ip': '142.250.185.78',
    })
    return d


NOVEL_ATTACKS = {
    'dns_tunnel':       ('DNS Tunneling (Unknown)',       dns_tunnel),
    'crypto_mining':    ('Crypto Mining C2 (Unknown)',    crypto_mining),
    'data_exfil':       ('Data Exfiltration (Unknown)',   data_exfiltration),
    'iot_botnet':       ('IoT Botnet (Unknown)',          iot_botnet),
    'slowloris':        ('Slowloris Variant (Unknown)',   slowloris_variant),
    'icmp_flood':       ('ICMP Flood Variant (Unknown)',  icmp_flood_variant),
    'lateral':          ('Lateral Movement (Unknown)',    lateral_movement),
}

NORMAL_TRAFFIC = {
    'browsing': ('Normal Web Browsing', normal_browsing),
    'https':    ('Normal HTTPS',        normal_https),
}


def randomise_ips(base: dict) -> dict:
    d = base.copy()
    d['source_ip'] = f"192.168.{random.randint(0,5)}.{random.randint(2,254)}"
    return d
