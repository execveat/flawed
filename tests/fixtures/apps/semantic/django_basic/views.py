"""Django views for route, input, effect, and check resolution tests.

Exercises:
  - Function-based views with @login_required
  - Class-based views (ListView, DetailView)
  - request.GET / request.POST input access
  - Model.save() / QuerySet operations
  - MiddlewareClassPattern via custom middleware
"""

from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils.safestring import mark_safe
from django.views import View
from django.views.decorators.http import require_http_methods

from .models import Article, User


# -- Function-based views ------------------------------------------------


def index(request):
    """Unprotected index view."""
    return JsonResponse({"message": "hello"})


@login_required
def user_list(request):
    """@login_required → AUTHENTICATION check.

    request.GET access → Query input source.
    User.objects.all() → DB_READ effect.
    """
    page = request.GET.get("page", "1")
    users = User.objects.all()
    return JsonResponse({"count": users.count(), "page": page})


@login_required
def user_detail(request, pk):
    """request path parameter pk → PathParam input source.

    User.objects.get(pk=pk) → DB_READ effect.
    """
    user = User.objects.get(pk=pk)
    return JsonResponse({"name": user.name, "email": user.email})


@login_required
@require_http_methods(["POST"])
def user_create(request):
    """request.POST access → Form input source.

    User.objects.create() → DB_WRITE effect.
    """
    name = request.POST["name"]
    email = request.POST.get("email", "")
    user = User.objects.create(name=name, email=email)
    user.save()
    return JsonResponse({"id": user.pk}, status=201)


@permission_required("articles.change_article")
def search(request, query):
    """@permission_required → AUTHORIZATION check.

    Path parameter query from URL regex.
    """
    results = Article.objects.filter(title__icontains=query)
    return JsonResponse({"results": list(results.values("id", "title"))})


# -- Class-based views ---------------------------------------------------


class ArticleListView(View):
    """Class-based view — dispatches by HTTP method.

    The provider declares ClassViewPattern on django.views.View.
    """

    def get(self, request):
        """GET → list articles (DB_READ)."""
        articles = Article.objects.all()
        return JsonResponse({"articles": list(articles.values("id", "title"))})

    def post(self, request):
        """POST → create article (DB_WRITE)."""
        title = request.POST["title"]
        body = request.POST.get("body", "")
        article = Article(title=title, body=body)
        article.save()
        return JsonResponse({"created": True}, status=201)


class ArticleDetailView(View):
    """Detail view with update and delete."""

    def get(self, request, pk):
        article = Article.objects.get(pk=pk)
        return JsonResponse({"title": article.title})

    def delete(self, request, pk):
        article = Article.objects.get(pk=pk)
        article.delete()
        return JsonResponse({"deleted": True})


# -- Sinks ---------------------------------------------------------------


def unsafe_view(request):
    """mark_safe(user_input) → XSS taint sink."""
    name = request.GET.get("name", "")
    safe_name = mark_safe(name)
    return JsonResponse({"name": safe_name})


def redirect_view(request):
    """redirect(user_input) → OPEN_REDIRECT taint sink."""
    next_url = request.GET.get("next", "/")
    return redirect(next_url)
