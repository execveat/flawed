"""Django model stubs for subclass effect resolution tests.

Model.save() and Model.delete() are inherited by User and Article.
The provider declares these as DB_WRITE / DB_DELETE on Model base.
"""


class Manager:
    """Stub for django.db.models.Manager."""

    def all(self):
        return QuerySet()

    def filter(self, **kwargs):
        return QuerySet()

    def get(self, **kwargs):
        return Model()

    def create(self, **kwargs):
        return Model()

    def count(self):
        return 0


class QuerySet:
    """Stub for django.db.models.QuerySet."""

    def filter(self, **kwargs):
        return self

    def values(self, *fields):
        return self

    def count(self):
        return 0

    def exists(self):
        return False

    def delete(self):
        pass

    def update(self, **kwargs):
        return 0

    def __iter__(self):
        return iter([])


class Model:
    """Stub for django.db.models.Model."""

    objects = Manager()
    pk = None

    def save(self, **kwargs):
        """Persist → DB_WRITE."""
        pass

    def delete(self, **kwargs):
        """Remove → DB_DELETE."""
        pass


class User(Model):
    """User model — inherits save()/delete() from Model."""

    objects = Manager()

    def __init__(self, name="", email=""):
        self.name = name
        self.email = email


class Article(Model):
    """Article model — inherits save()/delete() from Model."""

    objects = Manager()

    def __init__(self, title="", body=""):
        self.title = title
        self.body = body
