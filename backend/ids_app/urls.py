from django.urls import path
from . import views
from . import capture_views

urlpatterns = [
    path('predict/',                views.PredictView.as_view(),                name='predict'),
    path('alerts/',                 views.AlertListView.as_view(),               name='alerts'),
    path('alerts/<int:pk>/',        views.AlertDetailView.as_view(),             name='alert-detail'),
    path('alerts/<int:pk>/status/', views.AlertStatusView.as_view(),             name='alert-status'),
    path('blockchain/',             views.BlockchainView.as_view(),              name='blockchain'),
    path('blockchain/verify/',      views.BlockchainVerifyView.as_view(),        name='blockchain-verify'),
    path('stats/',                  views.StatsView.as_view(),                   name='stats'),
    path('simulate/',               views.SimulateView.as_view(),                name='simulate'),
    # Live capture
    path('capture/status/',         capture_views.CaptureStatusView.as_view(),  name='capture-status'),
    path('capture/recent/',         capture_views.RecentLiveAlertsView.as_view(), name='capture-recent'),
]
