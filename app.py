
import sqlite3
from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "YUEMC2015"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 7 * 24 * 3600
JWTManager(app)
CORS(app)

DB_PATH = "yue_account.db"
ALLOWED_REDIRECTS = ['http://acct.q2.us.ci']

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    db.commit()
    db.close()

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    u, p = data.get("username", "").strip(), data.get("password", "").strip()
    if not u or not p:
        return jsonify({"code": 400, "message": "用户名和密码不能为空"}), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        return jsonify({"code": 409, "message": "用户名已存在"}), 409
    db.execute("INSERT INTO users(username, password_hash) VALUES(?, ?)",
               (u, generate_password_hash(p)))
    db.commit()
    return jsonify({"code": 200, "message": "注册成功"}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    u, p = data.get("username", "").strip(), data.get("password", "").strip()
    if not u or not p:
        return jsonify({"code": 400, "message": "用户名和密码不能为空"}), 400
    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE username=?", (u,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], p):
        return jsonify({"code": 401, "message": "用户名或密码错误"}), 401
    token = create_access_token(identity=u)
    return jsonify({"code": 200, "data": {"username": u, "token": token}})

@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json() or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"code": 400, "message": "token不能为空"}), 400
    try:
        payload = decode_token(token)
        return jsonify({"code": 200, "data": {"username": payload["sub"]}})
    except Exception:
        return jsonify({"code": 401, "message": "token无效或已过期"}), 401

@app.route("/api/user/info", methods=["GET"])
def user_info():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"code": 401, "message": "未登录"}), 401
    try:
        payload = decode_token(token)
        u = payload["sub"]
    except Exception:
        return jsonify({"code": 401, "message": "token无效"}), 401
    db = get_db()
    row = db.execute("SELECT username, created_at FROM users WHERE username=?", (u,)).fetchone()
    if not row:
        return jsonify({"code": 404, "message": "用户不存在"}), 404
    return jsonify({"code": 200, "data": {"username": row["username"], "created_at": str(row["created_at"])}})

# ========== 新增：修改密码 ==========
@app.route("/api/change-password", methods=["POST"])
def change_password():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"code": 401, "message": "未登录"}), 401
    try:
        payload = decode_token(token)
        u = payload["sub"]
    except Exception:
        return jsonify({"code": 401, "message": "token无效"}), 401

    data = request.get_json() or {}
    old_password = data.get("old_password", "").strip()
    new_password = data.get("new_password", "").strip()

    if not old_password or not new_password:
        return jsonify({"code": 400, "message": "旧密码和新密码不能为空"}), 400

    if len(new_password) < 6:
        return jsonify({"code": 400, "message": "新密码至少6位"}), 400

    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE username=?", (u,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], old_password):
        return jsonify({"code": 401, "message": "旧密码错误"}), 401

    db.execute("UPDATE users SET password_hash=? WHERE username=?",
               (generate_password_hash(new_password), u))
    db.commit()
    return jsonify({"code": 200, "message": "密码修改成功"}), 200

# ========== 新增：注销账号 ==========
@app.route("/api/delete-account", methods=["POST"])
def delete_account():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"code": 401, "message": "未登录"}), 401
    try:
        payload = decode_token(token)
        u = payload["sub"]
    except Exception:
        return jsonify({"code": 401, "message": "token无效"}), 401

    data = request.get_json() or {}
    confirm_password = data.get("password", "").strip()

    if not confirm_password:
        return jsonify({"code": 400, "message": "请输入密码确认"}), 400

    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE username=?", (u,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], confirm_password):
        return jsonify({"code": 401, "message": "密码错误，无法注销"}), 401

    db.execute("DELETE FROM users WHERE username=?", (u,))
    db.commit()
    return jsonify({"code": 200, "message": "账号已注销"}), 200

@app.route("/")
def login_page():
    redirect_url = request.args.get("redirect", "")
    with open("login.html", encoding="utf-8") as f:
        html = f.read()

    if redirect_url and any(redirect_url.startswith(h) for h in ALLOWED_REDIRECTS):
        site_name = urlparse(redirect_url).hostname or redirect_url
        html = html.replace("<!-- VIEW_MODE -->", "oauth")
        html = html.replace("<!-- OAUTH_SITE -->", site_name)
        html = html.replace("<!-- REDIRECT_URL -->", redirect_url)
    else:
        html = html.replace("<!-- VIEW_MODE -->", "normal")
        html = html.replace("<!-- OAUTH_SITE -->", "")
        html = html.replace("<!-- REDIRECT_URL -->", "")

    return html, 200, {"Content-Type": "text/html;charset=utf-8"}

if __name__ == "__main__":
    init_db()
    print(f"\nYUE后端已启动: http://127.0.0.1:5000/login\n")
    app.run(debug=True, port=5000, use_reloader=False)
