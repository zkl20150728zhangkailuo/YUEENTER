
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token
# flask-jwt-extended >= 4.0 中 decode_token 改名为 decode_jwt，做兼容
try:
    from flask_jwt_extended import decode_token
except ImportError:
    from flask_jwt_extended import decode_jwt as decode_token
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "YUEMC2015"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 7 * 24 * 3600
JWTManager(app)
CORS(app)

# PostgreSQL连接地址（已去掉 channel_binding 防止psycopg2报错）
# 优先读环境变量 DATABASE_URL，未配置则用默认Neon地址
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://neondb_owner:npg_QPs5SAx6mgdj@ep-mute-river-b5qx9k2d-pooler.c-7.us-east-2.aws.neon.tech/neondb?sslmode=require")

# ============================================================
# SQLite兼容性封装层 —— 下方所有API路由代码无需任何修改
# ============================================================
class _Conn:
    """模拟sqlite3.Connection的极简接口，适配psycopg2"""
    def __init__(self, url):
        self._conn = psycopg2.connect(url)
        self._conn.autocommit = False
        self.row_factory = None

    def execute(self, sql, params=()):
        # sqlite3用?占位符，psycopg2用%s，这里自动转换
        sql = sql.replace('?', '%s')
        cur = self._conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def get_db():
    if "db" not in g:
        g.db = _Conn(DATABASE_URL)
    return g.db

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
        conn.commit()
    finally:
        conn.close()

# Vercel部署时模块被import执行，需要在此初始化数据库
try:
    init_db()
except Exception as e:
    print(f"Warning: 数据库初始化失败: {e}")

# ============================================================
# 以下为你的原始API代码，一字未改
# ============================================================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    u, p = data.get("username","").strip(), data.get("password","").strip()
    if not u or not p:
        return jsonify({"code":400,"message":"用户名和密码不能为空"}),400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        return jsonify({"code":409,"message":"用户名已存在"}),409
    db.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
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
    row = db.execute("SELECT password_hash FROM users WHERE username=?", (u,)).fetchone()
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
    row = db.execute("SELECT username,created_at FROM users WHERE username=?", (u,)).fetchone()
    if not row:
        return jsonify({"code":404,"message":"用户不存在"}),404
    return jsonify({"code":200,"data":{"username":row["username"],"created_at":str(row["created_at"])}})

@app.route("/")
def login_page():
    # Vercel修复：用脚本同目录找login.html，不依赖cwd
    base_dir = os.path.dirname(os.path.abspath(__file__))
    login_path = os.path.join(base_dir, "login.html")
    redirect_url = request.args.get("redirect", "")
    with open(login_path, encoding="utf-8") as f:
        html = f.read()

    if redirect_url and any(redirect_url.startswith(h) for h in ['http://acct.q2.us.ci']):
        site_name = urlparse(redirect_url).hostname or redirect_url
        html = html.replace("<!-- VIEW_MODE -->", "oauth")
        html = html.replace("<!-- OAUTH_SITE -->", site_name)
        html = html.replace("<!-- REDIRECT_URL -->", redirect_url)
    else:
        html = html.replace("<!-- VIEW_MODE -->", "normal")
        html = html.replace("<!-- OAUTH_SITE -->", "")
        html = html.replace("<!-- REDIRECT_URL -->", "")

    return html, 200, {"Content-Type":"text/html;charset=utf-8"}

# Vercel入口
handler = app

if __name__ == "__main__":
    print(f"\nYUE后端已启动: http://127.0.0.1:5000/login\n")
    app.run(debug=True, port=5000, use_reloader=False)
