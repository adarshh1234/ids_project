"""
ids_app/views.py  (Ganache edition — UPDATED)
=============================================
Update: Replaced single SAMPLE_ATTACKS list with ATTACK_POOLS dictionary.
Each attack type now has 3 different real attack pattern variants.
Every button click sends a randomly chosen variant — different feature
values each time — making the ML demo genuinely dynamic.
"""

import json
import random
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Alert
from .serializers import AlertSerializer, PredictSerializer
from blockchain.ganache_chain import get_ganache
from ml_model.predictor import get_predictor
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


@method_decorator(csrf_exempt, name='dispatch')
class PredictView(APIView):
    def post(self, request):
        ser = PredictSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        data           = ser.validated_data
        source_ip      = data.pop('source_ip', '192.168.1.1')
        destination_ip = data.pop('destination_ip', '10.0.0.1')

        predictor = get_predictor()
        result    = predictor.predict(data)

        if 'error' in result:
            return Response(result, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        alert = Alert.objects.create(
            source_ip      =str(source_ip),
            destination_ip =str(destination_ip),
            protocol       =data.get('protocol_type', 'tcp'),
            attack_type    =result['prediction'],
            attack_category=result['prediction'],
            confidence     =result['confidence'],
            severity       =result['severity'],
            description    =result['description'],
            anomaly_score  =result.get('anomaly_score'),
            is_unknown_attack=result.get('is_unknown_attack', False),
            detection_method=result.get('detection_method', 'supervised'),
            rf_prediction  =result.get('rf_prediction', result['prediction']),
        )
        alert.raw_features     = dict(data)
        alert.shap_explanation = result['shap_explanation']
        alert.top_features     = result['top_features']
        alert.probabilities    = result['probabilities']
        alert.save()

        ganache    = get_ganache()
        block_data = {
            'alert_id':        alert.id,
            'attack_category': result['prediction'],
            'severity':        result['severity'],
            'source_ip':       str(source_ip),
            'destination_ip':  str(destination_ip),
            'confidence':      result['confidence'],
            'top_features':    result['top_features'],
        }
        tx_result = ganache.add_alert(block_data)

        if 'error' not in tx_result:
            alert.blockchain_block_index = tx_result.get('block_number')
            alert.blockchain_hash        = tx_result.get('tx_hash', '')[:64]
            alert.save()

        return Response({
            'alert_id':    alert.id,
            'prediction':  result['prediction'],
            'confidence':  result['confidence'],
            'severity':    result['severity'],
            'description': result['description'],
            'probabilities': result['probabilities'],
            'top_features':  result['top_features'],
            'anomaly_score': result.get('anomaly_score'),
            'is_anomaly':    result.get('is_anomaly', False),
            'is_unknown_attack': result.get('is_unknown_attack', False),
            'detection_method':  result.get('detection_method', 'supervised'),
            'detection_detail':  result.get('detection_detail', ''),
            'rf_prediction': result.get('rf_prediction', result['prediction']),
            'blockchain': {
                'tx_hash':      tx_result.get('tx_hash'),
                'block_number': tx_result.get('block_number'),
                'block_hash':   tx_result.get('block_hash'),
                'gas_used':     tx_result.get('gas_used'),
                'contract':     tx_result.get('contract'),
                'network':      tx_result.get('network', 'Ganache Ethereum'),
                'status':       tx_result.get('status'),
                'error':        tx_result.get('error'),
            }
        }, status=status.HTTP_201_CREATED)


class AlertListView(APIView):
    def get(self, request):
        severity      = request.query_params.get('severity')
        category      = request.query_params.get('category')
        status_filter = request.query_params.get('status')
        limit         = int(request.query_params.get('limit', 50))
        qs = Alert.objects.all()
        if severity:      qs = qs.filter(severity=severity)
        if category:      qs = qs.filter(attack_category=category)
        if status_filter: qs = qs.filter(status=status_filter)
        return Response({'count': qs.count(), 'alerts': AlertSerializer(qs[:limit], many=True).data})


class AlertDetailView(APIView):
    def get(self, request, pk):
        try:    alert = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(AlertSerializer(alert).data)


class AlertStatusView(APIView):
    def patch(self, request, pk):
        try:    alert = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        new_status = request.data.get('status')
        if new_status not in ['new', 'acknowledged', 'resolved']:
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)
        alert.status = new_status
        alert.save()
        return Response({'id': alert.id, 'status': alert.status})


class BlockchainView(APIView):
    def get(self, request):
        try:
            ganache = get_ganache()
            print("DEBUG connected:", ganache._connected)
            print("DEBUG contract:", ganache.contract)
            info    = ganache.get_chain_info()
            print("DEBUG info:", info)
            alerts  = ganache.get_all_alerts()
            txs     = ganache.get_recent_transactions(20)
            return Response({'network_info': info, 'alerts': alerts, 'transactions': txs, 'total_alerts': len(alerts)})
        except Exception as e:
            print("DEBUG ERROR:", e)
            import traceback; traceback.print_exc()
            return Response({'error': str(e)}, status=500)


class BlockchainVerifyView(APIView):
    def get(self, request):
        ganache   = get_ganache()
        info      = ganache.get_chain_info()
        connected = info.get('connected', False)
        return Response({
            'valid':            connected,
            'network':          'Ganache Ethereum (localhost:7545)',
            'contract_address': info.get('contract_address'),
            'block_number':     info.get('block_number'),
            'alert_count':      info.get('alert_count', 0),
            'message': '✅ Ganache chain verified.' if connected else '❌ Cannot connect to Ganache!',
        })


class BlockchainAlertVerifyView(APIView):
    def get(self, request, alert_id):
        return Response(get_ganache().verify_alert(int(alert_id)))


class StatsView(APIView):
    def get(self, request):
        total       = Alert.objects.count()
        by_category = {c: Alert.objects.filter(attack_category=c).count() for c in ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']}
        by_severity = {s: Alert.objects.filter(severity=s).count() for s in ['info', 'warning', 'high', 'critical']}
        recent      = Alert.objects.order_by('-timestamp')[:5]
        ganache     = get_ganache()
        info        = ganache.get_chain_info()
        return Response({
            'total_alerts':      total,
            'by_category':       by_category,
            'by_severity':       by_severity,
            'unresolved':        Alert.objects.exclude(status='resolved').count(),
            'blockchain_blocks': info.get('block_number', 0),
            'chain_valid':       info.get('connected', False),
            'ganache_network':   info.get('network', 'Ganache Ethereum'),
            'contract_address':  info.get('contract_address', ''),
            'recent_alerts':     AlertSerializer(recent, many=True).data,
        })


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK POOLS — 3 real variants per attack type
# Each click randomly picks one → different features → different confidence
# All feature vectors are based on real NSL-KDD dataset patterns
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_POOLS = {

    # ── NORMAL ────────────────────────────────────────────────────────────────
    'normal': [

        # Variant 1: Normal HTTP web browsing
        {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
            'src_bytes': 232, 'dst_bytes': 8153, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 5, 'srv_count': 5, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 30,
            'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.03,
            'dst_host_srv_diff_host_rate': 0.04, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '172.16.0.1', 'destination_ip': '192.168.1.100',
        },

        # Variant 2: Normal FTP file transfer session
        {
            'duration': 12, 'protocol_type': 'tcp', 'service': 'ftp', 'flag': 'SF',
            'src_bytes': 105, 'dst_bytes': 4096, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 1, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 2, 'srv_count': 2, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 10,
            'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.1,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '10.0.0.2', 'destination_ip': '192.168.1.50',
        },

        # Variant 3: Normal DNS query (UDP)
        {
            'duration': 0, 'protocol_type': 'udp', 'service': 'domain', 'flag': 'SF',
            'src_bytes': 48, 'dst_bytes': 105, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 5,
            'dst_host_srv_count': 5, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.2,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '192.168.1.5', 'destination_ip': '8.8.8.8',
        },
    ],

    # ── DoS ───────────────────────────────────────────────────────────────────
    'dos': [

        # Variant 1: Neptune — SYN flood (half-open TCP connections)
        # Key signals: count=511, serror_rate=1.0, flag=S0, src_bytes=0
        {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 511, 'srv_count': 511, 'serror_rate': 1.0, 'srv_serror_rate': 1.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
            'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.01,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 1.0,
            'dst_host_srv_serror_rate': 1.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '10.0.0.5', 'destination_ip': '192.168.1.10',
        },

        # Variant 2: Smurf — ICMP broadcast amplification flood
        # Key signals: protocol=icmp, count=511, src_bytes=1032
        {
            'duration': 0, 'protocol_type': 'icmp', 'service': 'ecr_i', 'flag': 'SF',
            'src_bytes': 1032, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 511, 'srv_count': 511, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
            'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '10.0.0.8', 'destination_ip': '192.168.1.255',
        },

        # Variant 3: Teardrop — malformed overlapping UDP fragments
        # Key signals: wrong_fragment=3, protocol=udp, count=255
        {
            'duration': 0, 'protocol_type': 'udp', 'service': 'private', 'flag': 'SF',
            'src_bytes': 28, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 3,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 255, 'srv_count': 255, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 255,
            'dst_host_srv_count': 255, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '10.0.0.9', 'destination_ip': '192.168.1.15',
        },
    ],

    # ── PROBE ─────────────────────────────────────────────────────────────────
    'probe': [

        # Variant 1: Portsweep — scanning many ports on one host
        # Key signals: diff_srv_rate=0.98, dst_host_diff_srv_rate=0.98
        {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'finger', 'flag': 'S0',
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 0.02,
            'diff_srv_rate': 0.98, 'srv_diff_host_rate': 1.0, 'dst_host_count': 255,
            'dst_host_srv_count': 4, 'dst_host_same_srv_rate': 0.02,
            'dst_host_diff_srv_rate': 0.98, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 1.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.5,
            'dst_host_srv_rerror_rate': 1.0,
            'source_ip': '10.10.10.2', 'destination_ip': '192.168.0.50',
        },

        # Variant 2: IPsweep — pinging many hosts to map the network
        # Key signals: protocol=icmp, srv_diff_host_rate=0.6, dst_host_count=255
        {
            'duration': 0, 'protocol_type': 'icmp', 'service': 'eco_i', 'flag': 'SF',
            'src_bytes': 8, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.6, 'dst_host_count': 255,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 1.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.6, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '10.10.10.5', 'destination_ip': '192.168.0.1',
        },

        # Variant 3: Nmap — service version detection scan
        # Key signals: flag=RSTO, rerror_rate=1.0, diff_srv_rate=0.95
        {
            'duration': 1, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'RSTO',
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 3, 'srv_count': 3, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 0.05,
            'diff_srv_rate': 0.95, 'srv_diff_host_rate': 0.8, 'dst_host_count': 255,
            'dst_host_srv_count': 10, 'dst_host_same_srv_rate': 0.04,
            'dst_host_diff_srv_rate': 0.96, 'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.8, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.9,
            'dst_host_srv_rerror_rate': 1.0,
            'source_ip': '10.10.10.9', 'destination_ip': '192.168.0.75',
        },
    ],

    # ── R2L ───────────────────────────────────────────────────────────────────
    'r2l': [

        # Variant 1: Guess password — FTP brute force login attempts
        # Key signals: num_failed_logins=9, is_guest_login=1, logged_in=0
        {
            'duration': 299, 'protocol_type': 'tcp', 'service': 'ftp', 'flag': 'SF',
            'src_bytes': 1512, 'dst_bytes': 2368, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 2, 'num_failed_logins': 9, 'logged_in': 0,
            'num_compromised': 3, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 2, 'num_shells': 0, 'num_access_files': 2,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1,
            'count': 2, 'srv_count': 2, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 1.0, 'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 2,
            'dst_host_srv_count': 2, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 1.0,
            'dst_host_srv_rerror_rate': 1.0,
            'source_ip': '192.168.5.10', 'destination_ip': '192.168.1.20',
        },

        # Variant 2: Warezmaster — unauthorized large file transfer via FTP
        # Key signals: num_file_creations=10, is_guest_login=1, src_bytes=40000
        {
            'duration': 45, 'protocol_type': 'tcp', 'service': 'ftp_data', 'flag': 'SF',
            'src_bytes': 40000, 'dst_bytes': 2000, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 5, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 10, 'num_shells': 0, 'num_access_files': 5,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '192.168.5.20', 'destination_ip': '192.168.1.25',
        },

        # Variant 3: IMAP exploit — remote buffer overflow on mail server
        # Key signals: num_failed_logins=5, service=imap4, num_compromised=1
        {
            'duration': 5, 'protocol_type': 'tcp', 'service': 'imap4', 'flag': 'SF',
            'src_bytes': 2120, 'dst_bytes': 1020, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 3, 'num_failed_logins': 5, 'logged_in': 0,
            'num_compromised': 1, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 1,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 1,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.5, 'srv_rerror_rate': 0.5, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.5,
            'dst_host_srv_rerror_rate': 0.5,
            'source_ip': '192.168.5.30', 'destination_ip': '192.168.1.30',
        },
    ],

    # ── U2R ───────────────────────────────────────────────────────────────────
    'u2r': [

        # Variant 1: Buffer overflow — classic stack smashing privilege escalation
        # Key signals: root_shell=1, su_attempted=1, num_shells=2, num_root=1
        {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF',
            'src_bytes': 1274, 'dst_bytes': 1837, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 4, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 1, 'root_shell': 1, 'su_attempted': 1, 'num_root': 1,
            'num_file_creations': 0, 'num_shells': 2, 'num_access_files': 1,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '192.168.10.5', 'destination_ip': '192.168.1.1',
        },

        # Variant 2: Rootkit — attacker hides processes after gaining root via SSH
        # Key signals: num_root=3, num_file_creations=3, is_host_login=1, hot=6
        {
            'duration': 2, 'protocol_type': 'tcp', 'service': 'ssh', 'flag': 'SF',
            'src_bytes': 956, 'dst_bytes': 1280, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 6, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 3, 'root_shell': 1, 'su_attempted': 1, 'num_root': 3,
            'num_file_creations': 3, 'num_shells': 1, 'num_access_files': 3,
            'num_outbound_cmds': 0, 'is_host_login': 1, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '192.168.10.8', 'destination_ip': '192.168.1.1',
        },

        # Variant 3: Perl exploit — script-based privilege escalation via telnet
        # Key signals: num_shells=3, hot=8, num_root=2, su_attempted=1
        {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'telnet', 'flag': 'SF',
            'src_bytes': 724, 'dst_bytes': 1040, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 8, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 2, 'root_shell': 1, 'su_attempted': 1, 'num_root': 2,
            'num_file_creations': 1, 'num_shells': 3, 'num_access_files': 2,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'source_ip': '192.168.10.12', 'destination_ip': '192.168.1.1',
        },
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
# SIMULATE VIEWS — now use ATTACK_POOLS for dynamic random variant selection
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(csrf_exempt, name='dispatch')
class SimulateView(APIView):
    def post(self, request):
        attack_type = request.data.get('attack_type', 'random').lower()

        if attack_type == 'random':
            # Pick a random attack type, then a random variant from that pool
            pool   = random.choice(list(ATTACK_POOLS.values()))
            sample = random.choice(pool)
        else:
            pool   = ATTACK_POOLS.get(attack_type, ATTACK_POOLS['normal'])
            sample = random.choice(pool)

        # Separate IPs from feature data
        data               = {k: v for k, v in sample.items() if k not in ('source_ip', 'destination_ip')}
        data['source_ip']      = sample.get('source_ip', '192.168.1.1')
        data['destination_ip'] = sample.get('destination_ip', '10.0.0.1')

        predict_view = PredictView()
        request.data.update(data)
        return predict_view.post(request)


@method_decorator(csrf_exempt, name='dispatch')
class SimulateSpecificView(APIView):
    def post(self, request, attack_type):
        pool   = ATTACK_POOLS.get(attack_type.lower(), ATTACK_POOLS['normal'])
        sample = random.choice(pool)

        data               = {k: v for k, v in sample.items() if k not in ('source_ip', 'destination_ip')}
        data['source_ip']      = sample.get('source_ip', '192.168.1.1')
        data['destination_ip'] = sample.get('destination_ip', '10.0.0.1')

        predict_view = PredictView()
        request.data.update(data)
        return predict_view.post(request)