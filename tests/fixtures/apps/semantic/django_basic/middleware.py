"""Django middleware for MiddlewareClassPattern resolution tests.

Exercises class-based middleware detection: subclass of MiddlewareMixin
with process_request / process_response hook methods.
"""

import sys
from types import ModuleType

if "django.utils.deprecation" not in sys.modules:

    class _FallbackMiddlewareMixin:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            response = self.get_response(request)
            return response

    django_module = sys.modules.setdefault("django", ModuleType("django"))
    utils_module = sys.modules.setdefault("django.utils", ModuleType("django.utils"))
    deprecation_module = ModuleType("django.utils.deprecation")
    deprecation_module.MiddlewareMixin = _FallbackMiddlewareMixin
    utils_module.deprecation = deprecation_module
    django_module.utils = utils_module
    sys.modules["django.utils.deprecation"] = deprecation_module

from django.utils.deprecation import MiddlewareMixin


class AuthMiddleware(MiddlewareMixin):
    """Custom auth middleware — subclass of MiddlewareMixin.

    process_request should be detected as MIDDLEWARE_REQUEST hook.
    """

    def process_request(self, request):
        """Check auth token on every request."""
        token = request.META.get("HTTP_AUTHORIZATION")
        if not token:
            pass  # Would return 401 in real code


class LoggingMiddleware(MiddlewareMixin):
    """Logging middleware — both request and response hooks."""

    def process_request(self, request):
        """Log incoming request."""
        request.META.get("PATH_INFO")

    def process_response(self, request, response):
        """Log outgoing response."""
        response.setdefault("X-Logged", "1")
        return response
