"""DRF views exercising class attributes, request inputs, and responses.

Exercises:
  - ClassAttributeGuardPattern for permission_classes, authentication_classes,
    and throttle_classes
  - ClassViewPattern for APIView.as_view() URL registration
  - InputAttributePattern for request.query_params/request.data/request.FILES
  - EffectCallPattern for rest_framework.response.Response
"""

from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .permissions import ApiKeyAuthentication, BurstThrottle, OwnerPermission


class ProtectedAPIView(APIView):
    """APIView protected by DRF class-level guard attributes."""

    permission_classes = [IsAuthenticated, OwnerPermission]
    authentication_classes = [TokenAuthentication, SessionAuthentication, ApiKeyAuthentication]
    throttle_classes = [BurstThrottle]

    def get(self, request):
        account_id = request.query_params.get("account_id")
        return Response({"account_id": account_id})

    def post(self, request):
        username = request.data["username"]
        avatar = request.FILES.get("avatar")
        return Response({"username": username, "avatar": bool(avatar)}, status=201)


class OpenStatusView(APIView):
    """APIView with explicit empty permissions to exercise fail-open shape."""

    permission_classes = []
    authentication_classes = []

    def get(self, request):
        return Response({"status": "ok"})


@api_view(["GET"])
def decorated_status(request):
    """Function-based DRF route using @api_view."""
    actor = request.user
    return Response({"actor": str(actor)})
