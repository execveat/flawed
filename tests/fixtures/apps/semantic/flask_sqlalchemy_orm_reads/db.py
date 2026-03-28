"""Shared SQLAlchemy instance (the flask-sqlalchemy ``db`` singleton)."""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
