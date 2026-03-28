"""FLAW-172 intra-function transform-provenance fixtures.

A request value read into a local must keep its origin as it flows through an
intra-function transform (``email.lower()``), so that ``derived_from`` /
``flows_to`` / ``shares_origin`` resolve on the transformed local — while a
genuine transform is still *not* whole-value-preserving (a pure alias is).
"""

from flask import Flask, request

app = Flask(__name__)


def sink(value):
    return value


@app.route("/lookup", methods=["GET"])
def lookup():
    """One request value, two different transforms, plus a pure alias."""
    email = request.args.get("email", "")
    alias = email  # pure alias: preserves the whole value
    lowered = email.lower()  # transform: derives but does not preserve
    stripped = email.strip()  # second transform of the SAME logical input
    sink(alias)
    sink(lowered)
    sink(stripped)
    return "ok"
