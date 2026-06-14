from rest_framework import serializers
from .models import Alert, NetworkSample


class AlertSerializer(serializers.ModelSerializer):
    raw_features = serializers.SerializerMethodField()
    shap_explanation = serializers.SerializerMethodField()
    top_features = serializers.SerializerMethodField()
    probabilities = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = [
            'id', 'timestamp', 'source_ip', 'destination_ip', 'protocol',
            'attack_type', 'attack_category', 'confidence', 'severity',
            'status', 'description', 'raw_features', 'shap_explanation',
            'top_features', 'probabilities',
            'anomaly_score', 'is_unknown_attack', 'detection_method', 'rf_prediction',
            'blockchain_block_index', 'blockchain_hash',
        ]

    def get_raw_features(self, obj):
        return obj.raw_features

    def get_shap_explanation(self, obj):
        return obj.shap_explanation

    def get_top_features(self, obj):
        return obj.top_features

    def get_probabilities(self, obj):
        return obj.probabilities


class PredictSerializer(serializers.Serializer):
    """Input serializer for prediction endpoint."""
    duration = serializers.IntegerField(default=0)
    protocol_type = serializers.CharField(default='tcp')
    service = serializers.CharField(default='http')
    flag = serializers.CharField(default='SF')
    src_bytes = serializers.IntegerField(default=0)
    dst_bytes = serializers.IntegerField(default=0)
    land = serializers.IntegerField(default=0)
    wrong_fragment = serializers.IntegerField(default=0)
    urgent = serializers.IntegerField(default=0)
    hot = serializers.IntegerField(default=0)
    num_failed_logins = serializers.IntegerField(default=0)
    logged_in = serializers.IntegerField(default=0)
    num_compromised = serializers.IntegerField(default=0)
    root_shell = serializers.IntegerField(default=0)
    su_attempted = serializers.IntegerField(default=0)
    num_root = serializers.IntegerField(default=0)
    num_file_creations = serializers.IntegerField(default=0)
    num_shells = serializers.IntegerField(default=0)
    num_access_files = serializers.IntegerField(default=0)
    num_outbound_cmds = serializers.IntegerField(default=0)
    is_host_login = serializers.IntegerField(default=0)
    is_guest_login = serializers.IntegerField(default=0)
    count = serializers.IntegerField(default=1)
    srv_count = serializers.IntegerField(default=1)
    serror_rate = serializers.FloatField(default=0.0)
    srv_serror_rate = serializers.FloatField(default=0.0)
    rerror_rate = serializers.FloatField(default=0.0)
    srv_rerror_rate = serializers.FloatField(default=0.0)
    same_srv_rate = serializers.FloatField(default=1.0)
    diff_srv_rate = serializers.FloatField(default=0.0)
    srv_diff_host_rate = serializers.FloatField(default=0.0)
    dst_host_count = serializers.IntegerField(default=255)
    dst_host_srv_count = serializers.IntegerField(default=255)
    dst_host_same_srv_rate = serializers.FloatField(default=1.0)
    dst_host_diff_srv_rate = serializers.FloatField(default=0.0)
    dst_host_same_src_port_rate = serializers.FloatField(default=0.0)
    dst_host_srv_diff_host_rate = serializers.FloatField(default=0.0)
    dst_host_serror_rate = serializers.FloatField(default=0.0)
    dst_host_srv_serror_rate = serializers.FloatField(default=0.0)
    dst_host_rerror_rate = serializers.FloatField(default=0.0)
    dst_host_srv_rerror_rate = serializers.FloatField(default=0.0)
    # Optional meta
    source_ip = serializers.IPAddressField(default='192.168.1.1')
    destination_ip = serializers.IPAddressField(default='10.0.0.1')
