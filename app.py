
import os
import psycopg2
from psycopg2.extras import RealDictCursor
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

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://neondb_owner:npg_QPs5SAx6mgdj@ep-mute-river-b5qx9k2d-pooler.c-7.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require")
# 移除psycopg2不支持的参数
DATABASE_URL = DATABASE_URL.replace("&channel_binding=require", "").replace("channel_binding=require&", "").replace("channel_binding=require", "")
ALLOWED_REDIRECTS = ['http://acct.q2.us.ci']

# 轻量封装，保持与原sqlite3连接相似的接口（execute + commit）
class _DB:
    def __init__(self, conn):
        self.conn = conn
    def execute(self, query, params=()):
        cur = self.conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(query, params)
        return cur
    def commit(self):
        self.conn.commit()

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
    return _DB(g.db)

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
    finally:
        conn.close()

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    u, p = data.get("username","").strip(), data.get("password","").strip()
    if not u or not p:
        return jsonify({"code":400,"message":"用户名和密码不能为空"}),400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=%s", (u,)).fetchone():
        return jsonify({"code":409,"message":"用户名已存在"}),409
    db.execute("INSERT INTO users(username,password_hash) VALUES(%s,%s)",
               (u, generate_password_hash(p)))
    db.commit()
    return jsonify({"code":200,"message":"注册成功"}),201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    u, p = data.get("username","").strip(), data.get("password","").strip()
    if not u or not p:
        return jsonify({"code":400,"message":"用户名和密码不能为空"}),400
    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE username=%s", (u,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], p):
        return jsonify({"code":401,"message":"用户名或密码错误"}),401
    token = create_access_token(identity=u)
    return jsonify({"code":200,"data":{"username":u,"token":token}})

@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json() or {}
    token = data.get("token","").strip()
    if not token:
        return jsonify({"code":400,"message":"token不能为空"}),400
    try:
        payload = decode_token(token)
        return jsonify({"code":200,"data":{"username":payload["sub"]}})
    except Exception:
        return jsonify({"code":401,"message":"token无效或已过期"}),401

@app.route("/api/user/info", methods=["GET"])
def user_info():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    if not token:
        return jsonify({"code":401,"message":"未登录"}),401
    try:
        payload = decode_token(token)
        u = payload["sub"]
    except Exception:
        return jsonify({"code":401,"message":"token无效"}),401
    db = get_db()
    row = db.execute("SELECT username,created_at FROM users WHERE username=%s", (u,)).fetchone()
    if not row:
        return jsonify({"code":404,"message":"用户不存在"}),404
    return jsonify({"code":200,"data":{"username":row["username"],"created_at":str(row["created_at"])}})

# 获取脚本所在目录，确保在任何工作目录下都能找到login.html
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route("/")
def login_page():
    redirect_url = request.args.get("redirect", "")
    with open(os.path.join(_BASE_DIR, "login.html"), encoding="utf-8") as f:
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

    return html, 200, {"Content-Type":"text/html;charset=utf-8"}

# 确保数据库表已创建（Vercel部署时模块import会自动执行这里）
init_db()

# Vercel入口点
handler = app

if __name__ == "__main__":
    print(f"\nYUE后端已启动: http://127.0.0.1:5000/login\n")
    app.run(debug=True, port=5000, use_reloader=False)
