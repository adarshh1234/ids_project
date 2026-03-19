"""
ids_app/capture_views.py
========================
Extra Django API endpoints for the live capture status panel.
Add to ids_app/urls.py:
    path('capture/status/', views_capture.CaptureStatusView.as_view()),
    path('capture/recent/', views_capture.RecentLiveAlertsView.as_view()),
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Alert
from .serializers import AlertSerializer
from django.utils import timezone
from datetime import timedelta


class CaptureStatusView(APIView):
    """Returns recent capture activity metrics for the Live Monitor panel."""
    def get(self, request):
        now = timezone.now()
        last_minute = now - timedelta(minutes=1)
        last_5min   = now - timedelta(minutes=5)
        last_hour   = now - timedelta(hours=1)

        alerts_1m  = Alert.objects.filter(timestamp__gte=last_minute).count()
        alerts_5m  = Alert.objects.filter(timestamp__gte=last_5min).count()
        attacks_5m = Alert.objects.filter(
            timestamp__gte=last_5min
        ).exclude(attack_category='Normal').count()

        last_alert = Alert.objects.first()

        return Response({
            'alerts_last_1min':  alerts_1m,
            'alerts_last_5min':  alerts_5m,
            'attacks_last_5min': attacks_5m,
            'rate_per_min':      round(alerts_5m / 5, 1),
            'last_alert_time':   last_alert.timestamp if last_alert else None,
            'last_alert_type':   last_alert.attack_category if last_alert else None,
        })


class RecentLiveAlertsView(APIView):
    """Returns last N alerts for the live feed panel (default 20)."""
    def get(self, request):
        n = int(request.query_params.get('n', 20))
        alerts = Alert.objects.all()[:n]
        return Response(AlertSerializer(alerts, many=True).data)
