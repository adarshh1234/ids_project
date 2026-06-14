"""
test_pipeline.py
================
End-to-end IDS validation: normal traffic, known attacks, and unknown/novel attacks.

Usage:
    python test_pipeline.py                    # full test suite
    python test_pipeline.py --api http://localhost:8000
    python test_pipeline.py --only novel       # test unknown attacks only
    python test_pipeline.py --only normal      # test normal traffic only
"""

import argparse
import sys
import time
import requests

from novel_attacks import NOVEL_ATTACKS, NORMAL_TRAFFIC, randomise_ips

# Known attack templates from inject_attacks
KNOWN_ATTACKS = {
    'dos': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
        'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
        'is_host_login': 0, 'is_guest_login': 0,
        'count': 511, 'srv_count': 511, 'serror_rate': 1.0, 'srv_serror_rate': 1.0,
        'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
        'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        'dst_host_count': 255, 'dst_host_srv_count': 255,
        'dst_host_same_srv_rate': 1.0, 'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.01, 'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 1.0, 'dst_host_srv_serror_rate': 1.0,
        'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
        'source_ip': '10.0.0.5', 'destination_ip': '192.168.1.10',
    },
    'probe': {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'finger', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0, 'urgent': 0,
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
        'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
        'is_host_login': 0, 'is_guest_login': 0,
        'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
        'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 0.02,
        'diff_srv_rate': 0.98, 'srv_diff_host_rate': 1.0,
        'dst_host_count': 255, 'dst_host_srv_count': 4,
        'dst_host_same_srv_rate': 0.02, 'dst_host_diff_srv_rate': 0.98,
        'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 1.0,
        'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.5, 'dst_host_srv_rerror_rate': 1.0,
        'source_ip': '10.10.10.2', 'destination_ip': '192.168.0.50',
    },
}


class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def add(self, name, expected, actual, ok, detail=''):
        self.results.append({
            'name': name, 'expected': expected, 'actual': actual,
            'ok': ok, 'detail': detail,
        })
        if ok:
            self.passed += 1
        else:
            self.failed += 1

    def print_report(self):
        print("\n" + "=" * 70)
        print("  TEST RESULTS")
        print("=" * 70)
        for r in self.results:
            icon = "PASS" if r['ok'] else "FAIL"
            print(f"  [{icon}] {r['name']}")
            print(f"         Expected: {r['expected']} | Got: {r['actual']}")
            if r['detail']:
                print(f"         {r['detail']}")
        print("-" * 70)
        total = self.passed + self.failed
        rate = (self.passed / total * 100) if total else 0
        print(f"  {self.passed}/{total} passed ({rate:.0f}%)")
        print("=" * 70)
        return self.failed == 0


def predict(api_url, payload):
    resp = requests.post(api_url, json=payload, timeout=10)
    if resp.status_code != 201:
        raise RuntimeError(f"API {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def check_health(api_url):
    base = api_url.replace('/api/predict/', '')
    try:
        r = requests.get(f"{base}/api/capture/status/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def test_normal(api_url, results: TestResult):
    print("\n--- Normal Traffic Tests ---")
    for key, (label, fn) in NORMAL_TRAFFIC.items():
        payload = randomise_ips(fn())
        try:
            r = predict(api_url, payload)
            pred = r.get('prediction', '?')
            ok = pred == 'Normal'
            results.add(
                label, 'Normal', pred, ok,
                f"confidence={r.get('confidence')}% method={r.get('detection_method')}",
            )
        except Exception as e:
            results.add(label, 'Normal', 'ERROR', False, str(e))
        time.sleep(0.2)


def test_known(api_url, results: TestResult):
    print("\n--- Known Attack Tests ---")
    expectations = {'dos': 'DoS', 'probe': 'Probe'}
    for key, base in KNOWN_ATTACKS.items():
        payload = randomise_ips(base)
        try:
            r = predict(api_url, payload)
            pred = r.get('prediction', '?')
            expected = expectations[key]
            ok = expected in pred
            results.add(
                f"Known {key.upper()}", expected, pred, ok,
                f"confidence={r.get('confidence')}% anomaly={r.get('anomaly_score')}",
            )
        except Exception as e:
            results.add(f"Known {key.upper()}", expectations[key], 'ERROR', False, str(e))
        time.sleep(0.2)


def test_novel(api_url, results: TestResult):
    print("\n--- Unknown / Novel Attack Tests ---")
    for key, (label, fn) in NOVEL_ATTACKS.items():
        payload = randomise_ips(fn())
        try:
            r = predict(api_url, payload)
            pred = r.get('prediction', '?')
            is_unknown = r.get('is_unknown_attack', False)
            method = r.get('detection_method', '?')
            ok = is_unknown or pred == 'Unknown' or '(Novel)' in pred
            results.add(
                label, 'Unknown/Novel', pred, ok,
                f"method={method} anomaly_score={r.get('anomaly_score')} "
                f"is_unknown={is_unknown}",
            )
        except Exception as e:
            results.add(label, 'Unknown/Novel', 'ERROR', False, str(e))
        time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser(description='IDSGuard end-to-end test pipeline')
    parser.add_argument('--api', default='http://localhost:8000', help='Django base URL')
    parser.add_argument('--only', choices=['normal', 'known', 'novel', 'all'], default='all')
    args = parser.parse_args()

    api_url = args.api.rstrip('/') + '/api/predict/'

    print("=" * 70)
    print("  IDSGuard Production Test Pipeline")
    print("=" * 70)
    print(f"  API: {api_url}")

    if not check_health(args.api.rstrip('/') + '/api/predict/'.replace('/api/predict/', '')):
        base = args.api.rstrip('/')
        if not check_health(base):
            print("\n  ERROR: Django backend not reachable.")
            print("  Start with: cd backend && python manage.py runserver")
            sys.exit(1)

    print("  Backend: OK")
    results = TestResult()

    suites = {
        'normal': test_normal,
        'known':  test_known,
        'novel':  test_novel,
    }

    if args.only == 'all':
        for fn in suites.values():
            fn(api_url, results)
    else:
        suites[args.only](api_url, results)

    success = results.print_report()
    if not success:
        print("\n  Some tests failed. Ensure you ran: python train_model.py")
        sys.exit(1)
    print("\n  All tests passed. System is ready for production testing.")


if __name__ == '__main__':
    main()
