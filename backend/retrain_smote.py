"""
retrain_smote.py
================
Retrains the Random Forest with SMOTE oversampling to fix
R2L and U2R class imbalance.

Usage:
    python retrain_smote.py --train dataset\KDDTrain+.txt --test dataset\KDDTest+.txt

Requirements:
    pip install imbalanced-learn
"""

import os
import pickle
import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from collections import Counter

FEATURE_NAMES = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

CATEGORICAL_COLS = ['protocol_type','service','flag']

ATTACK_CATEGORY = {
    'normal':'Normal',
    'back':'DoS','land':'DoS','neptune':'DoS','pod':'DoS','smurf':'DoS',
    'teardrop':'DoS','apache2':'DoS','udpstorm':'DoS','processtable':'DoS',
    'worm':'DoS','mailbomb':'DoS',
    'ipsweep':'Probe','nmap':'Probe','portsweep':'Probe','satan':'Probe',
    'mscan':'Probe','saint':'Probe',
    'ftp_write':'R2L','guess_passwd':'R2L','imap':'R2L','multihop':'R2L',
    'phf':'R2L','spy':'R2L','warezclient':'R2L','warezmaster':'R2L',
    'sendmail':'R2L','named':'R2L','snmpgetattack':'R2L','snmpguess':'R2L',
    'xlock':'R2L','xsnoop':'R2L','httptunnel':'R2L',
    'buffer_overflow':'U2R','loadmodule':'U2R','perl':'U2R','rootkit':'U2R',
    'ps':'U2R','sqlattack':'U2R','xterm':'U2R',
}


def load_dataset(filepath):
    df = pd.read_csv(filepath, header=None, names=FEATURE_NAMES)
    df.drop(columns=['difficulty'], inplace=True)
    df['attack_category'] = df['label'].str.lower().map(
        lambda x: ATTACK_CATEGORY.get(x, 'Unknown')
    )
    df = df[df['attack_category'] != 'Unknown']
    return df


def preprocess(df, label_encoders=None, scaler=None, fit=True):
    df = df.copy()
    if fit:
        label_encoders = {}
        for col in CATEGORICAL_COLS:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le
    else:
        for col in CATEGORICAL_COLS:
            le = label_encoders[col]
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )

    feature_cols = [c for c in df.columns if c not in ('label','attack_category')]
    X = df[feature_cols].values
    y = df['attack_category'].values

    if fit:
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
    else:
        X = scaler.transform(X)

    return X, y, label_encoders, scaler, feature_cols


def retrain(train_path, test_path, output_dir='ml_model'):
    os.makedirs(output_dir, exist_ok=True)

    print("📂 Loading datasets...")
    train_df = load_dataset(train_path)
    test_df  = load_dataset(test_path)

    print(f"\nOriginal class distribution:")
    print(train_df['attack_category'].value_counts())

    print("\n⚙️  Preprocessing...")
    X_train, y_train, label_encoders, scaler, feature_cols = preprocess(train_df, fit=True)
    X_test,  y_test,  _,             _,      _            = preprocess(
        test_df, label_encoders=label_encoders, scaler=scaler, fit=False
    )

    print("\n🔄 Applying SMOTE oversampling...")
    print("   Before SMOTE:", Counter(y_train))

    # SMOTE strategy — upsample minority classes to at least 5000 each
    smote_strategy = {}
    class_counts   = Counter(y_train)
    target_count   = 5000
    for cls, count in class_counts.items():
        if count < target_count:
            smote_strategy[cls] = target_count

    if smote_strategy:
        sm      = SMOTE(sampling_strategy=smote_strategy, random_state=42, k_neighbors=3)
        X_train, y_train = sm.fit_resample(X_train, y_train)
        print("   After  SMOTE:", Counter(y_train))
    else:
        print("   No oversampling needed — all classes have enough samples")

    print("\n🌲 Training Random Forest with balanced data...")
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_split=4,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced',
    )
    rf.fit(X_train, y_train)

    print("\n📊 Evaluation on Test Set:")
    y_pred = rf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    print(f"   Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, y_pred))

    # Save
    with open(os.path.join(output_dir,'rf_model.pkl'),       'wb') as f: pickle.dump(rf, f)
    with open(os.path.join(output_dir,'scaler.pkl'),         'wb') as f: pickle.dump(scaler, f)
    with open(os.path.join(output_dir,'label_encoders.pkl'), 'wb') as f: pickle.dump(label_encoders, f)
    with open(os.path.join(output_dir,'feature_cols.pkl'),   'wb') as f: pickle.dump(feature_cols, f)

    print(f"\n✅ SMOTE-retrained model saved to '{output_dir}/'")
    return acc


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--train', default='dataset/KDDTrain+.txt')
    parser.add_argument('--test',  default='dataset/KDDTest+.txt')
    parser.add_argument('--out',   default='ml_model')
    args = parser.parse_args()
    retrain(args.train, args.test, args.out)
