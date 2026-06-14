"""
Anomaly detection configuration for hybrid IDS inference.
Thresholds are calibrated during training and saved to anomaly_config.pkl.
"""

ANOMALY_SEVERITY = 'critical'
ANOMALY_DESCRIPTION = (
    'Unknown or novel attack pattern detected. Traffic deviates significantly '
    'from learned normal behavior and does not match known attack signatures with '
    'high confidence. Requires immediate investigation.'
)

NOVEL_DESCRIPTION = (
    'Novel variant of a known attack category detected. Pattern is anomalous '
    'compared to training data — possible zero-day or modified attack tool.'
)

DETECTION_METHODS = {
    'supervised': 'Known attack classified by Random Forest',
    'anomaly': 'Unknown attack flagged by anomaly detector',
    'anomaly_override': 'Anomaly detector overrode normal classification',
    'hybrid': 'Known category with anomalous/novel pattern',
}
