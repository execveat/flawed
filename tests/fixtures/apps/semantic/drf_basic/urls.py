"""DRF URL configuration for executable semantic fixture coverage."""

from django.urls import path

from .views import OpenStatusView, ProtectedAPIView, decorated_status

urlpatterns = [
    path("account/", ProtectedAPIView.as_view(), name="account"),
    path("status/", OpenStatusView.as_view(), name="status"),
    path("decorated/", decorated_status, name="decorated-status"),
]
