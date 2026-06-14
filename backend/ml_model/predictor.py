"""
ml_model/predictor.py
=====================
Hybrid IDS inference:
  - Random Forest  → known attack classification
  - Isolation Forest → unknown / zero-day anomaly detection
  - SHAP           → explainability for supervised predictions
"""

import pickle
import shap
import numpy as np
import pandas as pd
from pathlib import Path

from .anomaly_config import (
    ANOMALY_SEVERITY,
    ANOMALY_DESCRIPTION,
    NOVEL_DESCRIPTION,
    DETECTION_METHODS,
)

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
    'Normal':  'info',
    'DoS':     'critical',
    'Probe':   'warning',
    'R2L':     'high',
    'U2R':     'critical',
    'Unknown': 'critical',
}

ATTACK_DESCRIPTIONS = {
    'Normal': 'This traffic appears to be legitimate network activity.',
    'DoS':    'Denial-of-Service attack detected. Attacker is flooding the network to exhaust resources.',
    'Probe':  'Probe/Scan attack detected. Attacker is surveilling the network to gather information.',
    'R2L':    'Remote-to-Local attack detected. Attacker is trying to gain local access from a remote machine.',
    'U2R':    'User-to-Root attack detected. Attacker is exploiting vulnerabilities to gain root/admin access.',
    'Unknown': ANOMALY_DESCRIPTION,
}

UNCERTAINTY_THRESHOLD = 0.60
MINORITY_THRESHOLD    = 0.15
MINORITY_CLASSES      = ['R2L', 'U2R']
HYBRID_CONFIDENCE_FLOOR = 0.70


class IDSPredictor:
    _instance = None

    def __init__(self):
        self.model           = None
        self.anomaly_model   = None
        self.anomaly_config  = None
        self.scaler          = None
        self.label_encoders  = None
        self.feature_cols    = None
        self.explainer       = None
        self._loaded         = False

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

            self.explainer = shap.TreeExplainer(self.model)

            anomaly_path = MODEL_DIR / 'anomaly_model.pkl'
            config_path  = MODEL_DIR / 'anomaly_config.pkl'
            if anomaly_path.exists() and config_path.exists():
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_model = pickle.load(f)
                with open(config_path, 'rb') as f:
                    self.anomaly_config = pickle.load(f)

            self._loaded = True
            return True
        except FileNotFoundError:
            return False

    def _encode_record(self, record: dict) -> np.ndarray:
        df = pd.DataFrame([record])

        for col in FEATURE_NAMES:
            if col not in df.columns:
                df[col] = 0
        df = df[FEATURE_NAMES]

        for col in CATEGORICAL_COLS:
            le  = self.label_encoders[col]
            val = str(df[col].iloc[0])
            df[col] = le.transform([val])[0] if val in le.classes_ else -1

        X = df[self.feature_cols].values
        return self.scaler.transform(X)

    def _rule_based_anomaly(self, record: dict) -> bool:
        """Heuristic checks for patterns unlikely in normal traffic."""
        count = record.get('count', 0)
        dst_bytes = record.get('dst_bytes', 0)
        src_bytes = record.get('src_bytes', 0)
        duration = record.get('duration', 0)
        serror = record.get('serror_rate', 0)
        diff_srv = record.get('diff_srv_rate', 0)
        num_failed = record.get('num_failed_logins', 0)
        wrong_frag = record.get('wrong_fragment', 0)

        if count > 300 and record.get('protocol_type') == 'icmp':
            return True
        if dst_bytes > 500000 and src_bytes < 5000:
            return True
        if duration > 3600 and record.get('service') == 'other' and dst_bytes > 100000:
            return True
        if serror > 0.8 and count > 100:
            return True
        if diff_srv > 0.9 and count > 50 and record.get('protocol_type') == 'udp':
            return True
        if num_failed > 15:
            return True
        if wrong_frag > 5:
            return True
        return False

    def _anomaly_score(self, X: np.ndarray) -> tuple:
        if self.anomaly_model is None:
            return 0.0, False

        score = float(self.anomaly_model.decision_function(X)[0])
        threshold = self.anomaly_config.get('anomaly_threshold', 0.0)
        is_anomaly = score < threshold or self.anomaly_model.predict(X)[0] == -1
        return score, is_anomaly

    def _hybrid_decision(self, rf_prediction, max_prob, is_anomaly, anomaly_score):
        if not is_anomaly:
            return rf_prediction, 'supervised', max_prob

        if rf_prediction == 'Normal' or max_prob < HYBRID_CONFIDENCE_FLOOR:
            anomaly_confidence = min(99.0, max(55.0, (1.0 - (anomaly_score + 0.5)) * 100))
            method = 'anomaly_override' if rf_prediction == 'Normal' else 'anomaly'
            return 'Unknown', method, anomaly_confidence / 100.0

        novel_confidence = max(max_prob, 0.75)
        return f'{rf_prediction} (Novel)', 'hybrid', novel_confidence

    def predict(self, record: dict) -> dict:
        if not self._loaded:
            if not self.load():
                return {'error': 'Model not loaded. Run train_model.py first.'}

        X = self._encode_record(record)

        rf_prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        classes       = list(self.model.classes_)
        max_prob      = float(max(probabilities))

        if max_prob < UNCERTAINTY_THRESHOLD:
            for minority_class in MINORITY_CLASSES:
                if minority_class in classes:
                    idx = classes.index(minority_class)
                    if float(probabilities[idx]) > MINORITY_THRESHOLD:
                        rf_prediction = minority_class
                        max_prob = float(probabilities[idx])
                        break

        anomaly_score, is_anomaly = self._anomaly_score(X)
        if self._rule_based_anomaly(record):
            is_anomaly = True

        prediction, detection_method, effective_prob = self._hybrid_decision(
            rf_prediction, max_prob, is_anomaly, anomaly_score
        )

        prob_dict  = {cls: float(round(prob * 100, 2)) for cls, prob in zip(classes, probabilities)}
        confidence = float(round(effective_prob * 100, 2))

        if prediction == 'Unknown':
            severity = ANOMALY_SEVERITY
            description = ANOMALY_DESCRIPTION
        elif '(Novel)' in prediction:
            base = prediction.replace(' (Novel)', '')
            severity = ATTACK_SEVERITY.get(base, 'high')
            description = NOVEL_DESCRIPTION
        else:
            severity = ATTACK_SEVERITY.get(prediction, 'info')
            description = ATTACK_DESCRIPTIONS.get(prediction, '')

        shap_values = self._get_shap(X, rf_prediction, classes)

        return {
            'prediction':        prediction,
            'rf_prediction':     rf_prediction,
            'confidence':        confidence,
            'probabilities':     prob_dict,
            'severity':          severity,
            'description':       description,
            'shap_explanation':  shap_values,
            'top_features':      self._top_features(shap_values),
            'anomaly_score':     round(anomaly_score, 4),
            'is_anomaly':        is_anomaly,
            'is_unknown_attack': prediction == 'Unknown' or '(Novel)' in prediction,
            'detection_method':  detection_method,
            'detection_detail':  DETECTION_METHODS.get(detection_method, detection_method),
        }

    def _get_shap(self, X, prediction, classes) -> dict:
        shap_values = self.explainer.shap_values(X)
        class_index = classes.index(prediction) if prediction in classes else 0

        if isinstance(shap_values, list):
            vals = shap_values[class_index][0]
        elif hasattr(shap_values, 'ndim') and shap_values.ndim == 3:
            vals = shap_values[0, :, class_index]
        else:
            vals = shap_values[0]

        return {
            col: float(val)
            for col, val in zip(self.feature_cols, vals)
        }

    def _top_features(self, shap_dict: dict, n: int = 10) -> list:
        sorted_feats = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)
        return [
            {
                'feature':    k,
                'shap_value': v,
                'impact':     'positive' if v > 0 else 'negative',
            }
            for k, v in sorted_feats[:n]
        ]

    def batch_predict(self, records: list) -> list:
        return [self.predict(r) for r in records]


def get_predictor() -> IDSPredictor:
    p = IDSPredictor.get_instance()
    p.load()
    return p
