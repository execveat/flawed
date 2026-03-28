"""SQLAlchemy-style model hierarchy for subclass resolution tests.

The base Model class has save() and delete() methods.  Subclasses
(User, Product) inherit these.  The Semantic API must detect effects
on subclass instances via MRO tracing.

Note: these are simplified stubs mimicking the interface, not
actual SQLAlchemy models.  The analysis is purely structural.
"""


class Model:
    """Base ORM model (mimics SQLAlchemy declarative base).

    The provider declares:
      EffectCallPattern(fqn="...Model.save", category="DB_WRITE")
      EffectCallPattern(fqn="...Model.delete", category="DB_DELETE")
    """

    def save(self):
        """Persist this object to the database → DB_WRITE."""
        pass

    def delete(self):
        """Remove this object from the database → DB_DELETE."""
        pass

    @classmethod
    def get_by_id(cls, item_id):
        """Look up by primary key → DB_READ."""
        return cls()

    @classmethod
    def query_all(cls):
        """Return all instances → DB_READ."""
        return []


class User(Model):
    """User model — inherits save() and delete() from Model."""

    def __init__(self, name="", email=""):
        self.name = name
        self.email = email


class Product(Model):
    """Product model — inherits save() and delete() from Model."""

    def __init__(self, name="", price=0.0):
        self.name = name
        self.price = price


class AdminUser(User):
    """Two-level subclass: AdminUser → User → Model.

    AdminUser().save() should still be detected as DB_WRITE.
    """

    def __init__(self, name="", email="", role="admin"):
        super().__init__(name, email)
        self.role = role
