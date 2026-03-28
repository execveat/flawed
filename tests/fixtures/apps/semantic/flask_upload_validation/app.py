"""Flask app: file-upload validation dimensions (FLAW-105).

Each route reads a ``FileUpload`` and validates a different *subset* of the
dimensions an upload should check (filename / extension / size / content), so
the upload-validation rule can be exercised across the full classification:

- ``upload_fully_validated``      — all four dimensions → no finding
- ``upload_missing_content``      — filename+extension+size, no content probe
- ``upload_filename_size_only``   — filename+size only (partial-validation shaped)
- ``upload_unvalidated``          — no validation at all → MEDIUM finding
- ``upload_inline_size_only``     — size via request.content_length / config (non-call)
- ``upload_inline_extension_only``— extension via os.path.splitext / .endswith (inline)

Validation helpers are named to match the upload-validation rule's per-dimension selectors; their
bodies are deliberately trivial — only the *call* matters to static analysis.
The two ``inline`` routes deliberately use the *non-call* idioms (a size guard
on ``request.content_length`` / ``MAX_CONTENT_LENGTH``, an inline
``os.path.splitext`` / ``.endswith`` extension check) that FLAW-175 added.
"""

import os

from flask import Flask, current_app, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/var/uploads"


def allowed_file(filename):
    """Extension/type allowlist check (matches the `extension` dimension)."""
    return filename.rsplit(".", 1)[-1].lower() in {"png", "jpg", "pdf"}


def validate_size(file_storage):
    """Size-limit check (matches the `size` dimension)."""
    file_storage.seek(0, 2)
    size = file_storage.tell()
    file_storage.seek(0)
    return size <= 5 * 1024 * 1024


def verify_image(file_storage):
    """Content/MIME probe (matches the `content` dimension)."""
    head = file_storage.read(512)
    file_storage.seek(0)
    return head[:4] in {b"\x89PNG", b"\xff\xd8\xff\xe0"}


@app.route("/upload/full", methods=["POST"])
def upload_fully_validated():
    """All four dimensions validated → the upload-validation rule must not fire."""
    f = request.files["document"]
    name = secure_filename(f.filename)
    if not allowed_file(name):
        return "bad type", 400
    if not validate_size(f):
        return "too big", 400
    if not verify_image(f):
        return "bad content", 400
    f.save(f"{UPLOAD_DIR}/{name}")
    return "ok"


@app.route("/upload/missing-content", methods=["POST"])
def upload_missing_content():
    """filename + extension + size validated; content probe absent → LOW."""
    f = request.files["document"]
    name = secure_filename(f.filename)
    if not allowed_file(name):
        return "bad type", 400
    if not validate_size(f):
        return "too big", 400
    f.save(f"{UPLOAD_DIR}/{name}")
    return "ok"


@app.route("/upload/filename-size-only", methods=["POST"])
def upload_filename_size_only():
    """filename + size only (partial-validation shaped): extension + content absent → LOW.

    The acceptance criterion: a handler that sanitizes the filename and limits
    size must NOT be reported as a *completely* unvalidated upload.
    """
    f = request.files["avatar"]
    name = secure_filename(f.filename)
    if not validate_size(f):
        return "too big", 400
    f.save(f"{UPLOAD_DIR}/{name}")
    return "ok"


@app.route("/upload/unvalidated", methods=["POST"])
def upload_unvalidated():
    """No validation across any dimension → MEDIUM finding."""
    f = request.files["payload"]
    f.save(f"{UPLOAD_DIR}/{f.filename}")
    return "ok"


@app.route("/upload/inline-size", methods=["POST"])
def upload_inline_size_only():
    """Size limited via the non-call ``request.content_length`` /
    ``MAX_CONTENT_LENGTH`` idiom only — no named size helper, no other
    dimension. The size dimension must be recognized from the guard condition,
    so this is a LOW partial (not a MEDIUM "without validation")."""
    f = request.files["document"]
    if (
        request.content_length
        and request.content_length > current_app.config["MAX_CONTENT_LENGTH"]
    ):
        return "too big", 413
    f.save(f"{UPLOAD_DIR}/{f.filename}")
    return "ok"


@app.route("/upload/inline-extension", methods=["POST"])
def upload_inline_extension_only():
    """Extension checked via the inline ``os.path.splitext`` / ``.endswith``
    idiom only — no named ``allowed_file`` helper, no other dimension. The
    extension dimension must be recognized from these calls, so this is a LOW
    partial (not a MEDIUM "without validation")."""
    f = request.files["document"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in {".png", ".jpg", ".pdf"}:
        return "bad type", 400
    if not f.filename.endswith((".png", ".jpg", ".pdf")):
        return "bad type", 400
    f.save(f"{UPLOAD_DIR}/{f.filename}")
    return "ok"
