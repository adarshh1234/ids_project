# IDSGuard — AI-Driven Intrusion Detection System
### Hybrid ML (Random Forest + Isolation Forest) + Explainable AI (SHAP) + Blockchain Audit Logging

> Submitted by: **Adarsh Anil** · 24MCA04

---

## 📋 Project Overview

IDSGuard is a production-inspired network intrusion detection system that uses a **hybrid
machine learning engine** — a **Random Forest** classifier for known attacks and an
**Isolation Forest** for unknown/zero-day threats — trained on the **NSL-KDD** dataset.
Every prediction is explained using **SHAP** values and immutably logged to an **Ethereum
blockchain** (Ganache) via a **Solidity smart contract**. Live network traffic is captured
in real time using **Scapy + Npcap**. An admin dashboard built with **Django + React**
provides real-time monitoring, alerts, blockchain audit trail, and manual prediction.

---



---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│               Layer 1 — Network Capture                             │
│   Real WiFi traffic / attack_simulator.py / novel_attacks.py        │
│   NIC → Npcap driver → Scapy → 41 NSL-KDD features extracted       │
└────────────────────────────┬────────────────────────────────────────┘
                             │ POST /api/predict/
┌────────────────────────────▼────────────────────────────────────────┐
│               Layer 2 — Django REST API (Port 8000)                 │
│   Receives features → validates → passes to ML engine               │
│   Saves alerts to SQLite → returns prediction response              │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│               Layer 3 — Hybrid ML Engine                            │
│                                                                     │
│   ┌─────────────────────┐      ┌──────────────────────────┐        │
│   │   Random Forest     │      │    Isolation Forest      │        │
│   │  Supervised         │      │    Unsupervised          │        │
│   │  5-class classifier │      │    Anomaly scorer        │        │
│   │  Known attacks      │      │    Zero-day detection    │        │
│   └──────────┬──────────┘      └────────────┬─────────────┘        │
│              │                              │                       │
│              └──────────┬───────────────────┘                       │
│                         ▼                                           │
│              Decision Logic + SHAP Explainability                   │
└──────────┬──────────────────────────────────────┬───────────────────┘
           │                                      │
┌──────────▼──────────┐              ┌────────────▼───────────────────┐
│  Layer 4 — SQLite   │              │  Layer 4 — Blockchain          │
│  All alerts stored  │              │  Web3.py → IDSAuditLog.sol     │
│  via Django ORM     │              │  → Ganache (localhost:7545)    │
└──────────┬──────────┘              └────────────┬───────────────────┘
           └─────────────────┬────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│               Layer 5 — React Frontend (Port 3000)                  │
│   Dashboard │ Live Monitor │ Alerts │ Predict │ Blockchain tab      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔀 Detection Decision Logic

| Random Forest says | Isolation Forest score | Final result |
|---|---|---|
| Normal | > -0.10 (normal) | ✅ Normal |
| DoS / Probe / R2L / U2R | > -0.10 | ⚠️ Known attack |
| Normal | < -0.10 (anomalous) | 🔴 Unknown (zero-day) |
| DoS / Probe | < -0.10 (anomalous) | 🔴 DoS Novel / Probe Novel |

---

## 🗂️ Project Structure

```
ids_project/
├── backend/
│   ├── ids_project/              # Django project config
│   │   ├── settings.py
│   │   └── urls.py
│   ├── ids_app/                  # Main Django app
│   │   ├── models.py             # Alert model
│   │   ├── views.py              # All REST API endpoints
│   │   ├── serializers.py        # DRF serializers
│   │   ├── auth_views.py         # Authentication endpoints
│   │   ├── capture_views.py      # Live capture status endpoints
│   │   └── urls.py               # URL routing
│   ├── blockchain/
│   │   ├── ganache_chain.py      # Web3.py + Ganache integration
│   │   ├── IDSAuditLog.sol       # Solidity smart contract
│   │   ├── deployment.json       # Deployed contract address + ABI
│   │   └── chain.py              # Blockchain utility functions
│   ├── ml_model/
│   │   ├── predictor.py          # Hybrid ML inference + SHAP
│   │   ├── anomaly_config.py     # Isolation Forest configuration
│   │   ├── rf_model.pkl          # Trained Random Forest
│   │   ├── anomaly_model.pkl     # Trained Isolation Forest
│   │   ├── scaler.pkl            # StandardScaler
│   │   ├── label_encoders.pkl    # Categorical encoders
│   │   ├── feature_cols.pkl      # Feature column order
│   │   └── anomaly_config.pkl    # Anomaly threshold config
│   ├── dataset/
│   │   ├── KDDTrain+.txt         # NSL-KDD training data
│   │   └── KDDTest+.txt          # NSL-KDD test data
│   ├── train_model.py            # Train Random Forest
│   ├── retrain_smote.py          # Retrain with SMOTE balancing
│   ├── manage.py                 # Django management
│   ├── db.sqlite3                # SQLite database
│   └── requirements.txt
│
├── frontend/
│   ├── public/index.html
│   └── src/
│       ├── App.js                # Router + sidebar layout
│       ├── pages/                # Dashboard, Alerts, Predict,
│       │                         # Blockchain, LiveMonitor pages
│       └── services/api.js       # Axios API calls
│
├── network_capture/
│   ├── capture.py                # Live Scapy packet capture agent
│   ├── attack_simulator.py       # 7-type attack traffic generator
│   ├── novel_attacks.py          # Unknown/zero-day attack generator
│   ├── inject_attacks.py         # Direct feature injection (no capture)
│   ├── test_pipeline.py          # Automated 11-test validation suite
│   ├── wifi_helper.py            # Network interface detection utility
│   └── requirements.txt
│
├── PRODUCTION.md                 # Production deployment guide
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.9+
- Node.js 16+
- Ganache GUI ([download here](https://trufflesuite.com/ganache/))
- Npcap ([download here](https://npcap.com/)) — for live packet capture
- NSL-KDD dataset files (`KDDTrain+.txt`, `KDDTest+.txt`)

---

### Step 1 — Backend Setup

```bash
cd ids_project/backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

---

### Step 2 — Train the ML Models

```bash
cd ids_project/backend
python train_model.py
```

**Expected output:**
```
Loading NSL-KDD dataset...
  Train: 125,973 records
  Classes: Normal=67343, DoS=45927, Probe=11656, R2L=995, U2R=52

Applying SMOTE for class balancing...
Training Random Forest...
Training Isolation Forest (anomaly detection)...

Evaluation on Test Set:
  Accuracy: ~99.x%

Model artifacts saved to ml_model/
  rf_model.pkl          — Random Forest
  anomaly_model.pkl     — Isolation Forest
  scaler.pkl            — StandardScaler
  label_encoders.pkl    — Categorical encoders
  feature_cols.pkl      — Feature column list
  anomaly_config.pkl    — Anomaly threshold config
```

---

### Step 3 — Start Ganache

1. Open Ganache GUI
2. Click **Quickstart**
3. Go to **Settings (gear icon) → Server tab**
4. Set **HOSTNAME** to `0.0.0.0` (required for Windows)
5. Keep **PORT** as `7545`
6. Click **Save and Restart**
7. Click **SAVE** (top right) to persist workspace

---

### Step 4 — Deploy Smart Contract + Start Django

```bash
cd ids_project/backend

# Deploy contract to Ganache (auto-detects and redeploys if needed)
python -c "from blockchain.ganache_chain import GanacheBlockchain; b = GanacheBlockchain(); print(b.get_chain_info())"

# Run database migrations
python manage.py migrate

# Start Django server
python manage.py runserver
```

Backend live at: **http://localhost:8000**

> ⚠️ Always run the contract deploy command before `manage.py runserver`.
> If Ganache restarts, it loses contract state — rerun the deploy command.

---

### Step 5 — Start React Frontend

```bash
cd ids_project/frontend
npm install
npm start
```

Dashboard opens at: **http://localhost:3000**

---

### Step 6 — Start Live Packet Capture (Optional, run as Administrator)

```bash
cd ids_project/network_capture

# Detect your network interface
python wifi_helper.py --detect

# Start capture (replace interface name with your detected interface)
python capture.py --iface "\Device\NPF_{YOUR-INTERFACE-ID}" --api http://localhost:8000
```

---

## 🧪 Testing the System

### Option A — Automated Test Pipeline (Recommended)

```bash
cd ids_project/network_capture
python test_pipeline.py
```

Expected: **11/11 tests passed (100%)**
- 2 normal traffic tests
- 2 known attack tests (DoS, Probe)
- 7 unknown/novel attack tests

---

### Option B — Inject Known Attacks

```bash
cd ids_project/network_capture

# Known attacks
python inject_attacks.py dos --n 3
python inject_attacks.py probe --n 3

# Unknown/novel attacks
python inject_attacks.py novel-all --n 2
```

---

### Option C — Simulate Real Attack Traffic (requires capture running)

```bash
cd ids_project/network_capture

python attack_simulator.py dos
python attack_simulator.py probe
python attack_simulator.py udp-flood
python attack_simulator.py icmp-flood
python attack_simulator.py slowloris
python attack_simulator.py brute-force
python attack_simulator.py exfil
python attack_simulator.py all        # run all 7 types
```

---

### Option D — Dashboard Simulation

1. Open http://localhost:3000
2. Click **Simulate Traffic** on the Dashboard
3. Go to **Alerts** to see detection results
4. Click any alert ID for full SHAP explanation
5. Visit **Blockchain** tab to see on-chain audit log

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/predict/` | Predict attack + SHAP + blockchain log |
| GET | `/api/alerts/` | List all alerts (filterable) |
| GET | `/api/alerts/<id>/` | Alert detail with SHAP explanation |
| PATCH | `/api/alerts/<id>/status/` | Update alert status |
| GET | `/api/blockchain/` | On-chain alerts + transaction history |
| GET | `/api/blockchain/verify/` | Verify chain integrity |
| GET | `/api/blockchain/verify/<id>/` | Verify specific alert on-chain |
| GET | `/api/stats/` | Dashboard aggregated statistics |
| POST | `/api/simulate/` | Simulate random traffic |
| POST | `/api/simulate/<attack_type>/` | Simulate specific attack type |
| GET | `/api/capture/status/` | Live capture agent status |
| GET | `/api/capture/recent/` | Recent live capture alerts |

---

## 🔗 Blockchain Design

**Technology:** Ethereum smart contract on Ganache local blockchain

**Smart contract:** `IDSAuditLog.sol` (Solidity 0.8)
- `logAlert()` — stores alert permanently on-chain
- `getAlert()` — retrieves alert by ID
- `getAllAlertIds()` — returns all logged alert IDs
- `verifyAlert()` — verifies alert existence on-chain
- `AlertLogged` event — emitted for each new alert

**Integration:** Web3.py v7 via HTTPProvider to Ganache at `http://127.0.0.1:7545`

**Each block stores:**
- Alert ID + timestamp
- Source / Destination IP
- Attack category + severity
- Confidence score (× 100 as integer)
- Top 3 SHAP features (JSON string)
- Transaction hash + block number

**Why blockchain over database:**
A database log can be deleted or altered by a compromised server. Blockchain records are cryptographically chained — altering any record invalidates the entire chain from that point, making tampering detectable and practically impossible.

---

## 🧠 ML Model Details

| Property | Value |
|---|---|
| Supervised model | Random Forest (scikit-learn) |
| Unsupervised model | Isolation Forest (scikit-learn) |
| Dataset | NSL-KDD (125,973 training records) |
| Features | 41 network traffic features |
| Classes | Normal, DoS, Probe, R2L, U2R |
| Class balancing | SMOTE (imbalanced-learn) |
| Explainability | SHAP TreeExplainer |
| Accuracy | ~99% on KDDTest+ |
| Anomaly threshold | -0.10 (Isolation Forest score) |

---

## 🌐 Live Capture Pipeline

```
Real WiFi traffic / attack_simulator.py
        ↓
NIC (Network Interface Card)
        ↓
Npcap kernel driver (promiscuous mode)
        ↓
Scapy — raw packet parsing
        ↓
Connection tracking table
(groups packets by src_ip, dst_ip, src_port, dst_port)
        ↓
41 NSL-KDD features extracted per connection
        ↓
POST /api/predict/
        ↓
Hybrid ML engine → classification
        ↓
Alert saved to SQLite + Blockchain
        ↓
React Live Monitor updated
```

---

## 🎯 Unknown Attack Types (novel_attacks.py)

| Attack | Pattern | How IF detects it |
|---|---|---|
| DNS Tunneling | Huge DNS packets, high frequency | Abnormal dst_bytes + count |
| Crypto Mining C2 | Constant small packets, odd ports | Unusual serror_rate + service |
| Data Exfiltration | Large slow outbound transfers | High dst_bytes + long duration |
| IoT Botnet | Many tiny connections to same IP | High count + low src_bytes |
| Slowloris | Many slow incomplete HTTP requests | High serror_rate + low bytes |
| ICMP Flood | Massive ICMP packet volume | High count + protocol=icmp |
| Lateral Movement | Sequential internal IP scanning | High dst_host_count + low bytes |

---

## 📊 Attack Categories

| Category | Description | NSL-KDD Examples |
|---|---|---|
| Normal | Legitimate network traffic | — |
| DoS | Resource exhaustion flooding | neptune, smurf, pod, teardrop |
| Probe | Reconnaissance / port scanning | portsweep, nmap, satan, ipsweep |
| R2L | Remote to Local unauthorized access | ftp_write, guess_passwd, phf |
| U2R | User to Root privilege escalation | buffer_overflow, rootkit, perl |
| Unknown | Zero-day / novel attack patterns | (not in NSL-KDD) |

---

## 🛠️ Technologies Used

| Layer | Technology |
|---|---|
| Packet capture | Scapy + Npcap |
| Supervised ML | scikit-learn Random Forest |
| Unsupervised ML | scikit-learn Isolation Forest |
| Class balancing | imbalanced-learn SMOTE |
| Explainability | SHAP TreeExplainer |
| Data processing | NumPy, Pandas |
| Backend | Django 4.2 + Django REST Framework |
| Database | SQLite (Django ORM) |
| Blockchain | Solidity 0.8 smart contract |
| Ethereum node | Ganache (local) |
| Web3 integration | Web3.py v7 |
| Solidity compiler | py-solc-x |
| Frontend | React 18 + React Router |
| HTTP client | Axios |
| Charts | Recharts |
| Icons | Lucide React |
| Dataset | NSL-KDD |

---

## ⚡ Quick Start (All Terminals)

```bash
# Terminal 1 — Ganache
# Open Ganache GUI → Quickstart → hostname 0.0.0.0 → Save

# Terminal 2 — Backend
cd "ids_project/backend"
python -c "from blockchain.ganache_chain import GanacheBlockchain; GanacheBlockchain()"
python manage.py runserver

# Terminal 3 — Frontend
cd "ids_project/frontend"
npm start

# Terminal 4 — Test pipeline
cd "ids_project/network_capture"
python test_pipeline.py

# Terminal 5 — Live capture (run as Administrator)
cd "ids_project/network_capture"
python capture.py --iface "\Device\NPF_{YOUR-INTERFACE}" --api http://localhost:8000
```

---



---

*Adarsh Anil · 24MCA04 · TKM College of Engineering · MCA Final Year Project*
