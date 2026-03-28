"""Path parent + secondary request-ID IDOR fixtures for g073 (FLAW-109).

Each route loads the path resource ``recording_id`` scoped to the authenticated
``current_user`` (correct), then reads a secondary ``template_id`` from a request
container.

- The *unsafe* routes load the template with a bare, unscoped lookup
  (``Template.query.get(template_id)``) — the classic BOLA shape an object-level authorization (IDOR) rule must flag,
  with the container correctly named.
- The *safe* route loads the template scoped to ``owner=current_user`` — an object-level authorization rule
  must NOT flag it (the false positive FLAW-109 removes).
"""

from flask import Flask, jsonify, request
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


class Recording(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String)


class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String)
    body = db.Column(db.String)


@app.route("/recordings/<recording_id>/transcript")
@login_required
def download_transcript_with_template(recording_id):
    """UNSAFE — secondary ``template_id`` from the query string, loaded unscoped."""
    Recording.query.filter_by(id=recording_id, owner=current_user).first()
    template_id = request.args.get("template_id")
    template = Template.query.get(template_id)  # no ownership/scope check
    return jsonify({"body": template.body})


@app.route("/recordings/<recording_id>/attach", methods=["POST"])
@login_required
def attach_template(recording_id):
    """UNSAFE — secondary ``template_id`` from the form body, loaded unscoped."""
    Recording.query.filter_by(id=recording_id, owner=current_user).first()
    template_id = request.form.get("template_id")
    template = Template.query.get(template_id)  # no ownership/scope check
    return jsonify({"attached": template.id})


@app.route("/recordings/<recording_id>/apply", methods=["POST"])
@login_required
def apply_json_template(recording_id):
    """UNSAFE — secondary ``template_id`` from the JSON body, loaded unscoped.

    Regression for the latent FN: an object-level authorization rule used to read the secondary key via
    ``getattr(source, "key")``, which is ``None`` for ``Json`` (its field is
    ``path``), so JSON-body IDs were silently missed.
    """
    Recording.query.filter_by(id=recording_id, owner=current_user).first()
    template_id = request.json.get("template_id")
    template = Template.query.get(template_id)  # no ownership/scope check
    return jsonify({"applied": template.id})


@app.route("/recordings/<recording_id>/safe", methods=["POST"])
@login_required
def safe_scoped_template(recording_id):
    """SAFE — secondary ``template_id`` loaded scoped to ``owner=current_user``.

    The secondary is bound to the authenticated principal, so this is NOT an
    IDOR and the rule must stay silent.
    """
    Recording.query.filter_by(id=recording_id, owner=current_user).first()
    template_id = request.form.get("template_id")
    template = Template.query.filter_by(id=template_id, owner=current_user).first()
    return jsonify({"ok": template.id})
