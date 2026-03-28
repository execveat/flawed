"""Access patterns fixture: attribute, subscript, augmented, delete, call mutators."""


class FakeSession:
    pass


class FakeRequest:
    pass


class FakeDB:
    pass


session = FakeSession()
request = FakeRequest()
db = FakeDB()
cache = {}
items = []
tokens = set()


class Store:
    def __init__(self):
        self.items = []


store = Store()


def read_attrs():
    name = request.args
    ct = request.content_type
    return name, ct


def write_attrs():
    session.user_id = 42
    session.role = "admin"


def read_subscript():
    val = session["user_id"]
    key = cache["token"]
    return val, key


def write_subscript():
    session["user_id"] = 42
    cache["token"] = "abc"


def augmented_attr():
    db.count += 1
    session.visits += 1


def augmented_subscript():
    cache["hits"] += 1
    session["count"] += 10


def delete_attr():
    del session.user_id
    del cache.token


def delete_subscript():
    del session["user_id"]
    del cache["token"]


def call_mutator():
    items.append("new")
    cache.update({"k": "v"})


def set_mutator():
    tokens.add("session-token")


def nested_receiver_mutator():
    store.items.extend(["a", "b"])


def non_mutating_method_call():
    return items.count("new")


def dynamic_getattr_access():
    return getattr(request, "args")
