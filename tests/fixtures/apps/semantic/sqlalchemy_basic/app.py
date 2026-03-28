"""SQLAlchemy ORM app: session operations, query patterns, raw SQL sinks.

Exercises:
  - EffectCallPattern (Session.add, commit, delete, query terminal methods)
  - TaintSinkPattern (text() for raw SQL)
  - FlowPropagatorPattern (filter/filter_by chains, Result fetch methods)
  - LifecycleDecoratorPattern (@event.listens_for)
"""

from sqlalchemy import Column, Integer, String, create_engine, event, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)


engine = create_engine("sqlite:///test.db")
SessionLocal = sessionmaker(bind=engine)


def create_user(name: str, email: str) -> User:
    """Session.add + commit → DB_WRITE effects."""
    db = SessionLocal()
    user = User(name=name, email=email)
    db.add(user)
    db.commit()
    return user


def get_user(user_id: int) -> User:
    """Session.query + first → DB_READ effect + flow propagation."""
    db = SessionLocal()
    return db.query(User).filter(User.id == user_id).first()


def search_users(name_pattern: str):
    """Query.filter_by → flow propagation, .all() terminal → DB_READ."""
    db = SessionLocal()
    return db.query(User).filter_by(name=name_pattern).all()


def update_user(user_id: int, new_name: str):
    """Session.merge → DB_WRITE effect."""
    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    user.name = new_name
    db.merge(user)
    db.flush()
    db.commit()


def delete_user(user_id: int):
    """Session.delete + commit → DB_DELETE + DB_WRITE effects."""
    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    db.delete(user)
    db.commit()


def raw_query(user_input: str):
    """text(user_input) → SQL_INJECTION taint sink."""
    db = SessionLocal()
    result = db.execute(text(user_input))
    return result.fetchall()


def safe_query():
    """text() with literal string — not a taint sink."""
    db = SessionLocal()
    result = db.execute(text("SELECT 1"))
    return result.scalar()


@event.listens_for(Session, "before_flush")
def before_flush_handler(session, flush_context, instances):
    """@event.listens_for → lifecycle SIGNAL hook."""
    pass


def cleanup():
    """Engine dispose → ENGINE_MANAGEMENT effect."""
    engine.dispose()
