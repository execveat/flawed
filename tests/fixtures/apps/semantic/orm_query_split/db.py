"""Shared flask-sqlalchemy ``db`` singleton (sibling-module import case)."""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
