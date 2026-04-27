from django.urls import path
from . import views
from . import capture_views
from . import auth_views

urlpatterns = [
    # Auth
    path('auth/login/',   auth_views.LoginView.as_view(),    name='login'),
    path('auth/logout/',  auth_views.LogoutView.as_view(),   name='logout'),
    path('auth/status/',  auth_views.AuthStatusView.as_view(), name='auth-status'),
    # IDS
    path('predict/',                    views.PredictView.as_view(),               name='predict'),
    path('alerts/',                     views.AlertListView.as_view(),              name='alerts'),
    path('alerts/<int:pk>/',            views.AlertDetailView.as_view(),            name='alert-detail'),
    path('alerts/<int:pk>/status/',     views.AlertStatusView.as_view(),            name='alert-status'),
    path('blockchain/',                 views.BlockchainView.as_view(),             name='blockchain'),
    path('blockchain/verify/',          views.BlockchainVerifyView.as_view(),       name='blockchain-verify'),
    path('blockchain/verify/<int:alert_id>/', views.BlockchainAlertVerifyView.as_view(), name='blockchain-alert-verify'),
    path('stats/',                      views.StatsView.as_view(),                  name='stats'),
    path('simulate/',                   views.SimulateView.as_view(),               name='simulate'),
    path('simulate/<str:attack_type>/', views.SimulateSpecificView.as_view(),       name='simulate-specific'),
    path('capture/status/',             capture_views.CaptureStatusView.as_view(),  name='capture-status'),
    path('capture/recent/',             capture_views.RecentLiveAlertsView.as_view(), name='capture-recent'),
]