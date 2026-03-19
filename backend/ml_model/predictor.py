"""
ml_model/predictor.py
=====================
Loads the trained Random Forest model and provides:
  - predict(record_dict) → prediction + SHAP explanation
"""

import os
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_DIR = Path(__file__).parent

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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
]

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

ATTACK_SEVERITY = {
    'Normal': 'info',
    'DoS': 'critical',
    'Probe': 'warning',
    'R2L': 'high',
    'U2R': 'critical',
}

ATTACK_DESCRIPTIONS = {
    'Normal': 'This traffic appears to be legitimate network activity.',
    'DoS': 'Denial-of-Service attack detected. Attacker is flooding the network to exhaust resources.',
    'Probe': 'Probe/Scan attack detected. Attacker is surveilling the network to gather information.',
    'R2L': 'Remote-to-Local attack detected. Attacker is trying to gain local access from a remote machine.',
    'U2R': 'User-to-Root attack detected. Attacker is exploiting vulnerabilities to gain root/admin access.',
}


class IDSPredictor:
    _instance = None

    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.feature_cols = None
        self.explainer = None
        self._loaded = False

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = IDSPredictor()
        return cls._instance

    def load(self):
        if self._loaded:
            return True
        try:
            with open(MODEL_DIR / 'rf_model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            with open(MODEL_DIR / 'scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
            with open(MODEL_DIR / 'label_encoders.pkl', 'rb') as f:
                self.label_encoders = pickle.load(f)
            with open(MODEL_DIR / 'feature_cols.pkl', 'rb') as f:
                self.feature_cols = pickle.load(f)
            self._loaded = True
            return True
        except FileNotFoundError:
            return False

    def _encode_record(self, record: dict) -> np.ndarray:
        df = pd.DataFrame([record])
        # Ensure all feature columns exist
        for col in FEATURE_NAMES:
            if col not in df.columns:
                df[col] = 0
        df = df[FEATURE_NAMES]

        for col in CATEGORICAL_COLS:
            le = self.label_encoders[col]
            val = str(df[col].iloc[0])
            df[col] = le.transform([val])[0] if val in le.classes_ else -1

        X = df[self.feature_cols].values
        return self.scaler.transform(X)

    def predict(self, record: dict) -> dict:
        if not self._loaded:
            if not self.load():
                return {'error': 'Model not loaded. Run train_model.py first.'}

        X = self._encode_record(record)

        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        classes = self.model.classes_
        prob_dict = {cls: float(round(prob * 100, 2)) for cls, prob in zip(classes, probabilities)}
        confidence = float(round(max(probabilities) * 100, 2))

        # SHAP explanation
        shap_values = self._get_shap(X, prediction, classes)

        return {
            'prediction': prediction,
            'confidence': confidence,
            'probabilities': prob_dict,
            'severity': ATTACK_SEVERITY.get(prediction, 'info'),
            'description': ATTACK_DESCRIPTIONS.get(prediction, ''),
            'shap_explanation': shap_values,
            'top_features': self._top_features(shap_values),
        }

    def _get_shap(self, X, prediction, classes) -> dict:
        # Always use feature importances * input as SHAP proxy (fast & reliable)
        importances = self.model.feature_importances_
        vals = (importances * X[0]).flatten()
        explanation = {
            col: float(val)
            for col, val in zip(self.feature_cols, vals)
        }
        return explanation

    def _top_features(self, shap_dict: dict, n=10) -> list:
        sorted_feats = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)
        return [
            {'feature': k, 'shap_value': v, 'impact': 'positive' if v > 0 else 'negative'}
            for k, v in sorted_feats[:n]
        ]

    def batch_predict(self, records: list) -> list:
        return [self.predict(r) for r in records]


def get_predictor() -> IDSPredictor:
    p = IDSPredictor.get_instance()
    p.load()
    return p
