from django.db import models
import json


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('new', 'New'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField(default='0.0.0.0')
    destination_ip = models.GenericIPAddressField(default='0.0.0.0')
    protocol = models.CharField(max_length=10, default='tcp')
    attack_type = models.CharField(max_length=50)
    attack_category = models.CharField(max_length=50)
    confidence = models.FloatField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    description = models.TextField(blank=True)

    # Stored as JSON strings
    _raw_features = models.TextField(db_column='raw_features', default='{}')
    _shap_explanation = models.TextField(db_column='shap_explanation', default='{}')
    _top_features = models.TextField(db_column='top_features', default='[]')
    _probabilities = models.TextField(db_column='probabilities', default='{}')

    # Blockchain reference
    blockchain_block_index = models.IntegerField(null=True, blank=True)
    blockchain_hash = models.CharField(max_length=64, blank=True)

    # Hybrid anomaly detection metadata
    anomaly_score = models.FloatField(null=True, blank=True)
    is_unknown_attack = models.BooleanField(default=False)
    detection_method = models.CharField(max_length=30, default='supervised')
    rf_prediction = models.CharField(max_length=50, blank=True, default='')

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.attack_category} @ {self.timestamp}"

    @property
    def raw_features(self):
        return json.loads(self._raw_features)

    @raw_features.setter
    def raw_features(self, value):
        self._raw_features = json.dumps(value)

    @property
    def shap_explanation(self):
        return json.loads(self._shap_explanation)

    @shap_explanation.setter
    def shap_explanation(self, value):
        self._shap_explanation = json.dumps(value)

    @property
    def top_features(self):
        return json.loads(self._top_features)

    @top_features.setter
    def top_features(self, value):
        self._top_features = json.dumps(value)

    @property
    def probabilities(self):
        return json.loads(self._probabilities)

    @probabilities.setter
    def probabilities(self, value):
        self._probabilities = json.dumps(value)


class NetworkSample(models.Model):
    """Stores raw network samples submitted for prediction."""
    timestamp = models.DateTimeField(auto_now_add=True)
    raw_data = models.TextField()
    alert = models.OneToOneField(Alert, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ['-timestamp']
