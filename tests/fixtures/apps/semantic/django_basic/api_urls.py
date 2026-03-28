"""Nested Django URL configuration referenced by django_basic.urls."""

from django.urls import path

from . import views

urlpatterns = [
    path("unsafe/", views.unsafe_view, name="api-unsafe"),
    path("redirect/", views.redirect_view, name="api-redirect"),
]
