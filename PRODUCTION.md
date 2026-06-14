# IDSGuard — Production Deployment Guide

## What Changed (Hybrid IDS)

The system now uses a **two-layer detection engine**:

| Layer | Model | Purpose |
|-------|-------|---------|
| Supervised | Random Forest | Classify known attacks (DoS, Probe, R2L, U2R) |
| Anomaly | Isolation Forest | Detect unknown / zero-day attack patterns |

### Detection Logic

1. **Known attack** — RF classifies with high confidence → use RF label
2. **Unknown attack** — Anomaly score below threshold + low RF confidence → flag as `Unknown`
3. **Novel variant** — RF suggests a category but pattern is anomalous → `DoS (Novel)` etc.
4. **Normal traffic** — Both models agree → `Normal`

---

## Quick Start

```bash
# 1. Train hybrid models (RF + anomaly detector)
cd backend
pip install -r requirements.txt
python train_model.py

# 2. Apply database migration
python manage.py migrate

# 3. Start backend
python manage.py runserver

# 4. Start frontend (separate terminal)
cd ../frontend && npm install && npm start
```

---

## Testing

### Automated test suite (no packet capture needed)

```bash
cd network_capture
pip install -r requirements.txt
python test_pipeline.py
```

Tests:
- Normal web/HTTPS traffic → should be `Normal`
- Known DoS/Probe → should match known categories
- 7 novel attack types → should flag as `Unknown` or `(Novel)`

### Inject attacks via API

```bash
python inject_attacks.py dos --n 5
python inject_attacks.py novel-all --n 3    # unknown attacks
python inject_attacks.py normal-all --n 5   # normal traffic
```

### Live packet capture (WiFi / Ethernet)

```bash
# Find your WiFi interface
python wifi_helper.py --detect

# Capture real normal traffic (browse web during capture)
python wifi_helper.py --capture-normal --duration 120

# Or use capture.py directly
python capture.py --iface "Wi-Fi" --api http://localhost:8000
```

### Multi-attack traffic simulation

```bash
# Run as Administrator on Windows
python attack_simulator.py --list
python attack_simulator.py dos
python attack_simulator.py probe
python attack_simulator.py udp-flood
python attack_simulator.py icmp-flood
python attack_simulator.py slowloris
python attack_simulator.py brute-force
python attack_simulator.py all
```

Pair with capture agent:
```bash
python capture.py --iface lo --api http://localhost:8000   # localhost attacks
python capture.py --iface "Wi-Fi" --api http://localhost:8000  # WiFi traffic
```

---

## Production Improvement Roadmap

### Already implemented
- Hybrid supervised + anomaly detection
- Unknown/zero-day attack flagging
- Multi-attack traffic simulator
- WiFi interface auto-detection
- End-to-end test pipeline
- Anomaly metadata in alerts API

### Recommended next steps

| Priority | Improvement | Why |
|----------|-------------|-----|
| High | Replace SQLite with PostgreSQL | Handle high alert volume |
| High | Add API authentication (JWT/API keys) | `/api/predict/` is currently open |
| High | Set `DEBUG=False`, use env vars for secrets | Security hardening |
| High | Add modern dataset (CIC-IDS2017, UNSW-NB15) | Better real-world accuracy |
| Medium | Deploy capture agent as Windows/Linux service | Always-on monitoring |
| Medium | Add model versioning + automated retraining | Drift management |
| Medium | Rate limiting + alert deduplication | Reduce noise |
| Medium | Prometheus/Grafana metrics export | Ops visibility |
| Low | Deep learning autoencoder for anomalies | Better OOD detection |
| Low | TLS/HTTPS payload inspection | Application-layer threats |

---

## API Response (new fields)

```json
{
  "prediction": "Unknown",
  "rf_prediction": "Normal",
  "confidence": 78.5,
  "anomaly_score": -0.32,
  "is_anomaly": true,
  "is_unknown_attack": true,
  "detection_method": "anomaly_override",
  "detection_detail": "Anomaly detector overrode normal classification"
}
```

---

## Windows Notes

- Run capture/simulator **as Administrator** (Npcap required)
- Install Npcap: https://npcap.com/
- WiFi interface is usually named `Wi-Fi` on Windows
- Use `python wifi_helper.py --list` to confirm
