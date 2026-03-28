"""Semantic spec helpers — path constants only.

Session-scoped fixtures live in tests/conftest.py. Do NOT define fixtures
or call ``open_repo()`` here. Receive fixtures by name in test parameters.
"""

from __future__ import annotations

from pathlib import Path

# Re-export fixture path constants for test assertions that check file paths.
FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "apps" / "semantic"

FLASK_BASIC = FIXTURES / "flask_basic"
FLASK_ADD_URL_RULE = FIXTURES / "flask_add_url_rule"
FLASK_ALIASED = FIXTURES / "flask_aliased"
FLASK_BLUEPRINTS = FIXTURES / "flask_blueprints"
FLASK_PACKAGE_BLUEPRINT = FIXTURES / "flask_package_blueprint"
FLASK_INDIRECT = FIXTURES / "flask_indirect"
FLASK_SUBCLASSED = FIXTURES / "flask_subclassed"
FASTAPI_BASIC = FIXTURES / "fastapi_basic"
DJANGO_BASIC = FIXTURES / "django_basic"
DRF_BASIC = FIXTURES / "drf_basic"
FLASK_INIT_APP = FIXTURES / "flask_init_app"
