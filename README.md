# IDSGuard — AI-Driven Intrusion Detection System
### with Explainable AI (SHAP) + Blockchain Audit Logging

> Submitted by: **Adarsh Anil** · 24MCA04

---

## 📋 Project Overview

This system detects network intrusions using a **Random Forest** classifier trained on the
**NSL-KDD** dataset. Every prediction is explained using **SHAP** values and immutably
logged to a private **blockchain** ledger. An admin dashboard built with **Django + React**
provides real-time monitoring, alerts, and audit trail verification.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (Port 3000)               │
│  Dashboard │ Alerts │ Predict │ Blockchain Explorer         │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API (axios)
┌────────────────────────▼────────────────────────────────────┐
│                 Django Backend (Port 8000)                  │
│                                                             │
│  /api/predict/     ──►  ML Model (Random Forest)            │
│                          └──► SHAP Explainer                │
│                          └──► Blockchain Logger             │
│  /api/alerts/      ──►  SQLite Database                     │
│  /api/blockchain/  ──►  chain.json (SHA-256 PoW)            │
│  /api/stats/       ──►  Dashboard aggregates                │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Project Structure

```
ids_project/
├── backend/
│   ├── ids_project/          # Django project config
│   │   ├── settings.py
│   │   └── urls.py
│   ├── ids_app/              # Main Django app
│   │   ├── models.py         # Alert, NetworkSample models
│   │   ├── views.py          # All REST API endpoints
│   │   ├── serializers.py
│   │   └── urls.py
│   ├── blockchain/
│   │   └── chain.py          # SHA-256 PoW blockchain
│   ├── ml_model/
│   │   └── predictor.py      # RF inference + SHAP
│   ├── train_model.py        # ← Run this FIRST
│   └── requirements.txt
│
├── frontend/
│   ├── public/index.html
│   └── src/
│       ├── App.js            # Router + sidebar layout
│       ├── pages/
│       │   ├── Dashboard.js      # Stats, charts, recent alerts
│       │   ├── Alerts.js         # Filterable alert list
│       │   ├── AlertDetail.js    # SHAP explanation + blockchain
│       │   ├── Predict.js        # Manual traffic prediction
│       │   └── BlockchainPage.js # Block explorer
│       └── services/api.js   # Axios API calls
│
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.9+
- Node.js 16+
- The NSL-KDD dataset files:
  - `KDDTrain_.txt`
  - `KDDTest_.txt`

---

### Step 1 — Backend Setup

```bash
cd ids_project/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

### Step 2 — Train the ML Model

> Place `KDDTrain_.txt` and `KDDTest_.txt` in the `backend/` folder.

```bash
cd ids_project/backend

python train_model.py --train KDDTrain_.txt --test KDDTest_.txt
```

**Expected output:**
```
📂 Loading datasets...
   Train: 125,973 records
   Test : 22,544 records
   Classes: {'Normal': 67343, 'DoS': 45927, 'Probe': 11656, 'R2L': 995, 'U2R': 52}

⚙️  Preprocessing...

🌲 Training Random Forest...

📊 Evaluation on Test Set:
   Accuracy: ~99.x%

✅ Model artifacts saved to 'ml_model/'
```

This creates:
- `ml_model/rf_model.pkl`     — Trained Random Forest
- `ml_model/scaler.pkl`       — StandardScaler
- `ml_model/label_encoders.pkl` — Categorical encoders
- `ml_model/feature_cols.pkl` — Feature column list

---

### Step 3 — Run Django Backend

```bash
cd ids_project/backend

# Run database migrations
python manage.py makemigrations
python manage.py migrate

# Create admin superuser (optional)
python manage.py createsuperuser

# Start Django development server
python manage.py runserver
```

Backend will be live at: **http://localhost:8000**

---

### Step 4 — Run React Frontend

```bash
cd ids_project/frontend

# Install Node packages
npm install

# Start React development server
npm start
```

Dashboard will open at: **http://localhost:3000**

---

## 🔌 API Endpoints

| Method | Endpoint                    | Description                        |
|--------|-----------------------------|------------------------------------|
| POST   | `/api/predict/`             | Predict attack + SHAP + blockchain |
| GET    | `/api/alerts/`              | List alerts (filterable)           |
| GET    | `/api/alerts/<id>/`         | Alert detail with SHAP             |
| PATCH  | `/api/alerts/<id>/status/`  | Update alert status                |
| GET    | `/api/blockchain/`          | All blockchain blocks              |
| GET    | `/api/blockchain/verify/`   | Verify chain integrity             |
| GET    | `/api/stats/`               | Dashboard statistics               |
| POST   | `/api/simulate/`            | Simulate random traffic            |

---

## 🧪 Testing the System

### Option A — Use the Dashboard
1. Open http://localhost:3000
2. Click **"Simulate Traffic"** on the Dashboard
3. Go to **Alerts** to see the detection result
4. Click any alert **ID** to see the full SHAP explanation
5. Visit **Blockchain** tab to see the audit log

### Option B — Use the Predict Page
1. Go to **Predict** in the sidebar
2. Select a preset: `Neptune (DoS)` or `Portsweep (Probe)`
3. Click **"Run Prediction + SHAP"**
4. View the classification result, SHAP bar chart, and probability scores

### Option C — Direct API call
```bash
curl -X POST http://localhost:8000/api/simulate/
```

---

## 🔗 Blockchain Design

- **Algorithm**: SHA-256 with Proof-of-Work (2 leading zeros)
- **Storage**: `blockchain/chain.json` (persisted to disk)
- **Tamper detection**: Hash recomputation on every load
- **Each block stores**:
  - Alert ID + timestamp
  - Source/Destination IP
  - Attack category + confidence
  - Severity level
  - Top 3 SHAP features
  - Previous block hash (chain link)

---

## 🧠 ML Model Details

| Property       | Value                          |
|----------------|-------------------------------|
| Algorithm      | Random Forest                  |
| Dataset        | NSL-KDD (125,973 train records)|
| Features       | 41 network traffic features    |
| Classes        | Normal, DoS, Probe, R2L, U2R   |
| Explainability | SHAP TreeExplainer             |
| Accuracy       | ~99% on KDDTest_               |

---

## 📊 Attack Categories

| Category | Description                              | Example Attacks        |
|----------|------------------------------------------|------------------------|
| Normal   | Legitimate network traffic               | —                      |
| DoS      | Denial of Service — resource exhaustion  | neptune, smurf, pod    |
| Probe    | Network scanning / surveillance          | portsweep, nmap, satan |
| R2L      | Remote-to-Local — unauthorized access    | ftp_write, guess_passwd|
| U2R      | User-to-Root — privilege escalation      | buffer_overflow, rootkit|

---

## 🛠️ Technologies Used

| Layer          | Technology                  |
|----------------|-----------------------------|
| ML Model       | scikit-learn (Random Forest) |
| Explainability | SHAP (TreeExplainer)         |
| Backend        | Django 4.x + Django REST Framework |
| Database       | SQLite                       |
| Blockchain     | Custom SHA-256 PoW (Python)  |
| Frontend       | React 18 + React Router      |
| Charts         | Recharts                     |
| Icons          | Lucide React                 |

---

*Adarsh Anil · 24MCA04 · MCA Project*
