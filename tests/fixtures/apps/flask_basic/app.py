"""Minimal Flask app: routes, request handling, database write."""

from flask import Flask, g, jsonify, request, session

app = Flask(__name__)


def get_db():
    return g.get("db")


@app.route("/users", methods=["GET"])
def list_users():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return jsonify(users)


@app.route("/users", methods=["POST"])
def create_user():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    db = get_db()
    db.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    db.commit()
    return jsonify({"status": "created"}), 201


@app.route("/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    data = request.json
    email = data.get("email")
    db = get_db()
    db.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
    db.commit()
    return jsonify({"status": "updated"})


@app.route("/profile", methods=["GET"])
def profile():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not logged in"}), 401
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(user)
