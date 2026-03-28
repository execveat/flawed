"""FastAPI dependency functions for DI resolution tests."""

from fastapi import Depends


def get_db():
    """Provides a database session — lifecycle_and_input dependency."""
    # In real code: yield db; db.close()
    return object()  # stub


def get_settings(db=Depends(get_db)):
    """Nested dependency: depends on get_db.

    The engine must resolve the full DI graph:
      handler → get_settings → get_db
    """
    return {"debug": False}


def get_cache():
    """Provides a cache client — simple dependency."""
    return object()  # stub
