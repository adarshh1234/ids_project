"""
ids_app/views.py
================
REST API endpoints:
  POST /api/predict/          — Predict attack type + SHAP + log to blockchain
  GET  /api/alerts/           — List all alerts
  GET  /api/alerts/<id>/      — Alert detail with full SHAP
  PATCH /api/alerts/<id>/status/ — Update alert status
  GET  /api/blockchain/       — All blockchain blocks
  GET  /api/blockchain/verify/ — Verify chain integrity
  GET  /api/stats/            — Dashboard statistics
  POST /api/simulate/         — Simulate random network traffic
"""

import random
import time
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Alert, NetworkSample
from .serializers import AlertSerializer, PredictSerializer
from blockchain.chain import get_blockchain
from ml_model.predictor import get_predictor


# ── Prediction ────────────────────────────────────────────────────────────────

class PredictView(APIView):
    def post(self, request):
        ser = PredictSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        data = ser.validated_data
        source_ip = data.pop('source_ip', '192.168.1.1')
        destination_ip = data.pop('destination_ip', '10.0.0.1')

        predictor = get_predictor()
        result = predictor.predict(data)

        if 'error' in result:
            return Response(result, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        # Persist alert
        alert = Alert.objects.create(
            source_ip=str(source_ip),
            destination_ip=str(destination_ip),
            protocol=data.get('protocol_type', 'tcp'),
            attack_type=result['prediction'],
            attack_category=result['prediction'],
            confidence=result['confidence'],
            severity=result['severity'],
            description=result['description'],
        )
        alert.raw_features = dict(data)
        alert.shap_explanation = result['shap_explanation']
        alert.top_features = result['top_features']
        alert.probabilities = result['probabilities']
        alert.save()

        # Log to blockchain
        bc = get_blockchain()
        block_data = {
            'alert_id': alert.id,
            'timestamp': str(alert.timestamp),
            'source_ip': str(source_ip),
            'destination_ip': str(destination_ip),
            'attack_category': result['prediction'],
            'confidence': result['confidence'],
            'severity': result['severity'],
            'top_features': result['top_features'][:3],
        }
        block = bc.add_block(block_data)
        alert.blockchain_block_index = block.index
        alert.blockchain_hash = block.hash
        alert.save()

        return Response({
            'alert_id': alert.id,
            'prediction': result['prediction'],
            'confidence': result['confidence'],
            'severity': result['severity'],
            'description': result['description'],
            'probabilities': result['probabilities'],
            'top_features': result['top_features'],
            'blockchain': {
                'block_index': block.index,
                'block_hash': block.hash,
            }
        }, status=status.HTTP_201_CREATED)


# ── Alerts ────────────────────────────────────────────────────────────────────

class AlertListView(APIView):
    def get(self, request):
        severity = request.query_params.get('severity')
        category = request.query_params.get('category')
        status_filter = request.query_params.get('status')
        limit = int(request.query_params.get('limit', 50))

        qs = Alert.objects.all()
        if severity:
            qs = qs.filter(severity=severity)
        if category:
            qs = qs.filter(attack_category=category)
        if status_filter:
            qs = qs.filter(status=status_filter)

        alerts = AlertSerializer(qs[:limit], many=True).data
        return Response({'count': qs.count(), 'alerts': alerts})


class AlertDetailView(APIView):
    def get(self, request, pk):
        try:
            alert = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(AlertSerializer(alert).data)


class AlertStatusView(APIView):
    def patch(self, request, pk):
        try:
            alert = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        new_status = request.data.get('status')
        if new_status not in ['new', 'acknowledged', 'resolved']:
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
        alert.status = new_status
        alert.save()
        return Response({'id': alert.id, 'status': alert.status})


# ── Blockchain ────────────────────────────────────────────────────────────────

class BlockchainView(APIView):
    def get(self, request):
        bc = get_blockchain()
        return Response({
            'chain_length': len(bc.chain),
            'is_valid': bc.is_valid(),
            'blocks': bc.get_all_blocks(),
        })


class BlockchainVerifyView(APIView):
    def get(self, request):
        bc = get_blockchain()
        valid = bc.is_valid()
        return Response({
            'valid': valid,
            'chain_length': len(bc.chain),
            'message': '✅ Chain integrity verified.' if valid else '❌ Chain has been tampered!',
        })


# ── Dashboard Stats ───────────────────────────────────────────────────────────

class StatsView(APIView):
    def get(self, request):
        total = Alert.objects.count()
        by_category = {}
        by_severity = {}
        for cat in ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']:
            by_category[cat] = Alert.objects.filter(attack_category=cat).count()
        for sev in ['info', 'warning', 'high', 'critical']:
            by_severity[sev] = Alert.objects.filter(severity=sev).count()

        recent = Alert.objects.order_by('-timestamp')[:5]
        bc = get_blockchain()

        return Response({
            'total_alerts': total,
            'by_category': by_category,
            'by_severity': by_severity,
            'unresolved': Alert.objects.exclude(status='resolved').count(),
            'blockchain_blocks': len(bc.chain),
            'chain_valid': bc.is_valid(),
            'recent_alerts': AlertSerializer(recent, many=True).data,
        })


# ── Simulate Traffic ──────────────────────────────────────────────────────────

SAMPLE_ATTACKS = [
    # neptune (DoS)
    {'duration':0,'protocol_type':'tcp','service':'private','flag':'S0','src_bytes':0,'dst_bytes':0,
     'land':0,'wrong_fragment':0,'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':0,
     'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,'num_file_creations':0,
     'num_shells':0,'num_access_files':0,'num_outbound_cmds':0,'is_host_login':0,'is_guest_login':0,
     'count':511,'srv_count':511,'serror_rate':1.0,'srv_serror_rate':1.0,'rerror_rate':0.0,
     'srv_rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,'srv_diff_host_rate':0.0,
     'dst_host_count':255,'dst_host_srv_count':255,'dst_host_same_srv_rate':1.0,
     'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':0.01,'dst_host_srv_diff_host_rate':0.0,
     'dst_host_serror_rate':1.0,'dst_host_srv_serror_rate':1.0,'dst_host_rerror_rate':0.0,
     'dst_host_srv_rerror_rate':0.0,
     'source_ip':'10.0.0.5','destination_ip':'192.168.1.10'},
    # normal http
    {'duration':0,'protocol_type':'tcp','service':'http','flag':'SF','src_bytes':232,'dst_bytes':8153,
     'land':0,'wrong_fragment':0,'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':1,
     'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,'num_file_creations':0,
     'num_shells':0,'num_access_files':0,'num_outbound_cmds':0,'is_host_login':0,'is_guest_login':0,
     'count':5,'srv_count':5,'serror_rate':0.2,'srv_serror_rate':0.2,'rerror_rate':0.0,
     'srv_rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,'srv_diff_host_rate':0.0,
     'dst_host_count':30,'dst_host_srv_count':255,'dst_host_same_srv_rate':1.0,
     'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':0.03,'dst_host_srv_diff_host_rate':0.04,
     'dst_host_serror_rate':0.03,'dst_host_srv_serror_rate':0.01,'dst_host_rerror_rate':0.0,
     'dst_host_srv_rerror_rate':0.01,
     'source_ip':'172.16.0.1','destination_ip':'192.168.1.100'},
    # portsweep (Probe)
    {'duration':1,'protocol_type':'tcp','service':'finger','flag':'S0','src_bytes':0,'dst_bytes':0,
     'land':0,'wrong_fragment':0,'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':0,
     'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,'num_file_creations':0,
     'num_shells':0,'num_access_files':0,'num_outbound_cmds':0,'is_host_login':0,'is_guest_login':0,
     'count':1,'srv_count':1,'serror_rate':1.0,'srv_serror_rate':1.0,'rerror_rate':0.0,
     'srv_rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,'srv_diff_host_rate':1.0,
     'dst_host_count':255,'dst_host_srv_count':4,'dst_host_same_srv_rate':0.02,
     'dst_host_diff_srv_rate':0.06,'dst_host_same_src_port_rate':0.0,'dst_host_srv_diff_host_rate':1.0,
     'dst_host_serror_rate':0.0,'dst_host_srv_serror_rate':0.0,'dst_host_rerror_rate':0.5,
     'dst_host_srv_rerror_rate':1.0,
     'source_ip':'10.10.10.2','destination_ip':'192.168.0.50'},
]


class SimulateView(APIView):
    def post(self, request):
        sample = random.choice(SAMPLE_ATTACKS)
        predict_view = PredictView()
        request._full_data = sample
        request.data.update(sample)
        return predict_view.post(request)
