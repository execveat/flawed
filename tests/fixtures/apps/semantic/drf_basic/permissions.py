"""DRF guard classes for class-attribute guard fixture coverage."""

from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission
from rest_framework.throttling import BaseThrottle


class OwnerPermission(BasePermission):
    """Project-local permission class resolved through BasePermission."""

    def has_permission(self, request, view):
        account_id = request.query_params.get("account_id")
        return account_id == request.user.account_id


class ApiKeyAuthentication(BaseAuthentication):
    """Project-local authentication class resolved through BaseAuthentication."""

    def authenticate(self, request):
        token = request.auth
        if token is None:
            return None
        return (request.user, token)


class BurstThrottle(BaseThrottle):
    """Project-local throttle class resolved through BaseThrottle."""

    def allow_request(self, request, view):
        return True
