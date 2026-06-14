"""
train_model.py
==============
Trains a Random Forest classifier on the NSL-KDD dataset.
Run this script once to generate rf_model.pkl, scaler.pkl, label_encoders.pkl.

Usage:
    python train_model.py --train KDDTrain_.txt --test KDDTest_.txt
"""

import os
import sys
import pickle
import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ── NSL-KDD feature names ─────────────────────────────────────────────────────
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

# Attack category mapping (5-class) 
ATTACK_CATEGORY = {
    'normal': 'Normal',
    # DoS
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'worm': 'DoS', 'mailbomb': 'DoS',
    # Probe
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
}


def load_dataset(filepath):
    df = pd.read_csv(filepath, header=None, names=FEATURE_NAMES)
    df.drop(columns=['difficulty'], inplace=True)
    df['attack_category'] = df['label'].str.lower().map(
        lambda x: ATTACK_CATEGORY.get(x, 'Unknown')
    )
    return df


def preprocess(df, label_encoders=None, scaler=None, fit=True):
    df = df.copy()

    # Encode categorical columns
    if fit:
        label_encoders = {}
        for col in CATEGORICAL_COLS:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le
    else:
        for col in CATEGORICAL_COLS:
            le = label_encoders[col]
            # Handle unseen labels gracefully
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )

    feature_cols = [c for c in df.columns if c not in ('label', 'attack_category')]
    X = df[feature_cols].values
    y = df['attack_category'].values

    if fit:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
    else:
        X = scaler.transform(X)

    return X, y, label_encoders, scaler, feature_cols


def train(train_path, test_path, output_dir='ml_model'):
    os.makedirs(output_dir, exist_ok=True)

    print("📂 Loading datasets...")
    train_df = load_dataset(train_path)
    test_df  = load_dataset(test_path)

    print(f"   Train: {len(train_df):,} records")
    print(f"   Test : {len(test_df):,} records")
    print(f"   Classes: {train_df['attack_category'].value_counts().to_dict()}")

    print("\n⚙️  Preprocessing...")
    X_train, y_train, label_encoders, scaler, feature_cols = preprocess(train_df, fit=True)
    X_test,  y_test,  _,             _,      _            = preprocess(
        test_df, label_encoders=label_encoders, scaler=scaler, fit=False
    )

    print("\n🌲 Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    rf.fit(X_train, y_train)

    print("\n📊 Evaluation on Test Set:")
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"   Accuracy: {acc * 100:.2f}%")
    print("\n", classification_report(y_test, y_pred))

    # Save artifacts
    with open(os.path.join(output_dir, 'rf_model.pkl'), 'wb') as f:
        pickle.dump(rf, f)
    with open(os.path.join(output_dir, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    with open(os.path.join(output_dir, 'label_encoders.pkl'), 'wb') as f:
        pickle.dump(label_encoders, f)
    with open(os.path.join(output_dir, 'feature_cols.pkl'), 'wb') as f:
        pickle.dump(feature_cols, f)

    print("\n🔍 Training Anomaly Detector (Isolation Forest on normal traffic)...")
    normal_mask = y_train == 'Normal'
    X_normal = X_train[normal_mask]
    print(f"   Normal samples for anomaly baseline: {len(X_normal):,}")

    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples='auto',
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_normal)

    normal_scores = iso_forest.decision_function(X_normal)
    anomaly_threshold = float(np.percentile(normal_scores, 5))
    print(f"   Anomaly threshold (5th percentile): {anomaly_threshold:.4f}")

    attack_mask = y_test != 'Normal'
    if attack_mask.any():
        attack_scores = iso_forest.decision_function(X_test[attack_mask])
        attack_anomaly_rate = float((attack_scores < anomaly_threshold).mean() * 100)
        print(f"   Known attacks flagged as anomalous: {attack_anomaly_rate:.1f}%")

    with open(os.path.join(output_dir, 'anomaly_model.pkl'), 'wb') as f:
        pickle.dump(iso_forest, f)
    with open(os.path.join(output_dir, 'anomaly_config.pkl'), 'wb') as f:
        pickle.dump({
            'anomaly_threshold': anomaly_threshold,
            'contamination': 0.05,
            'normal_samples': len(X_normal),
        }, f)

    print(f"\n✅ Model artifacts saved to '{output_dir}/'")
    print("   • rf_model.pkl          — supervised classifier")
    print("   • anomaly_model.pkl     — unknown attack detector")
    print("   • anomaly_config.pkl    — calibrated thresholds")
    return acc


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--train', default='dataset/KDDTrain+.txt')
    parser.add_argument('--test',  default='dataset/KDDTest+.txt')
    parser.add_argument('--out',   default='ml_model')
    args = parser.parse_args()
    train(args.train, args.test, args.out)
