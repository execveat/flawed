"""Django URL configuration for ImperativeRoutePattern tests.

Exercises:
  - ImperativeRoutePattern with urlpatterns list
  - path() and re_path() entries
  - include() for nested URL confs
"""

from django.urls import include, path, re_path

from . import views

urlpatterns = [
    # Function-based views
    path("", views.index, name="index"),
    path("users/", views.user_list, name="user-list"),
    path("users/<int:pk>/", views.user_detail, name="user-detail"),
    path("users/create/", views.user_create, name="user-create"),
    # Class-based views
    path("articles/", views.ArticleListView.as_view(), name="article-list"),
    path("articles/<int:pk>/", views.ArticleDetailView.as_view(), name="article-detail"),
    # Regex URL
    re_path(r"^search/(?P<query>.+)/$", views.search, name="search"),
    # Nested includes
    path("api/", include("tests.fixtures.apps.semantic.django_basic.api_urls")),
]
