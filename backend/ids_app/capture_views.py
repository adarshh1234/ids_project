"""
ids_app/capture_views.py
========================
API endpoints consumed by LiveMonitor.jsx:
  GET /api/capture/status/   → rate stats + last alert info
  GET /api/capture/recent/   → last N alerts (newest first)

These were missing entirely, causing the Live Monitor page to show
"Backend Offline" even when Django was running correctly.
"""

from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import Alert
from .serializers import AlertSerializer


class CaptureStatusView(APIView):
    """
    Returns live capture statistics used by the LiveMonitor status cards.
    Computes rates from the Alert table — no separate capture process needed.
    """
    def get(self, request):
        now       = timezone.now()
        last_1min = now - timedelta(minutes=1)
        last_5min = now - timedelta(minutes=5)

        alerts_1 = Alert.objects.filter(timestamp__gte=last_1min)
        alerts_5 = Alert.objects.filter(timestamp__gte=last_5min)

        attacks_5 = alerts_5.exclude(attack_category='Normal').count()

        last_alert = Alert.objects.order_by('-timestamp').first()

        # Alerts per minute averaged over the last 5 minutes
        total_5 = alerts_5.count()
        rate_per_min = round(total_5 / 5, 1)

        return Response({
            'rate_per_min':      rate_per_min,
            'alerts_last_1min':  alerts_1.count(),
            'alerts_last_5min':  total_5,
            'attacks_last_5min': attacks_5,
            'last_alert_type':   last_alert.attack_category if last_alert else None,
            'last_alert_time':   last_alert.timestamp.isoformat() if last_alert else None,
        })


class RecentLiveAlertsView(APIView):
    """
    Returns the N most recent alerts for the live feed table.
    Query param: ?n=30  (default 30, max 100)
    """
    def get(self, request):
        n = min(int(request.query_params.get('n', 30)), 100)
        alerts = Alert.objects.order_by('-timestamp')[:n]
        return Response(AlertSerializer(alerts, many=True).data)
