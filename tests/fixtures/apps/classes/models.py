"""Class hierarchy: single, multiple inheritance, abstract."""

from abc import ABC, abstractmethod


class Base:
    def save(self):
        pass

    def delete(self):
        pass


class Timestamped:
    created_at = None
    updated_at = None

    def touch(self):
        pass


class User(Timestamped, Base):
    def __init__(self, name):
        self.name = name

    def greet(self):
        return f"Hi, {self.name}"


class Admin(User):
    def promote(self, user):
        pass


class Serializable(ABC):
    @abstractmethod
    def to_dict(self):
        pass


class APIUser(Serializable, User):
    def to_dict(self):
        return {"name": self.name}
