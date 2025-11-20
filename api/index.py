from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from supabase import create_client
import os, bcrypt, jwt, random, string, datetime, smtplib
from email.mime.text import MIMEText

# ------------------ 配置 ------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
JWT_SECRET = os.environ.get("JWT_SECRET", "supersecret")

# SMTP 6 个账号
SMTP_ACCOUNTS = [
    {"host": os.environ.get("SMTP_HOST_1"), "port": int(os.environ.get("SMTP_PORT_1", 587)),
     "user": os.environ.get("SMTP_USER_1"), "pass": os.environ.get("SMTP_PASS_1"), "from": os.environ.get("SMTP_FROM_1")},
    {"host": os.environ.get("SMTP_HOST_2"), "port": int(os.environ.get("SMTP_PORT_2", 587)),
     "user": os.environ.get("SMTP_USER_2"), "pass": os.environ.get("SMTP_PASS_2"), "from": os.environ.get("SMTP_FROM_2")},
    {"host": os.environ.get("SMTP_HOST_3"), "port": int(os.environ.get("SMTP_PORT_3", 587)),
     "user": os.environ.get("SMTP_USER_3"), "pass": os.environ.get("SMTP_PASS_3"), "from": os.environ.get("SMTP_FROM_3")},
    {"host": os.environ.get("SMTP_HOST_4"), "port": int(os.environ.get("SMTP_PORT_4", 587)),
     "user": os.environ.get("SMTP_USER_4"), "pass": os.environ.get("SMTP_PASS_4"), "from": os.environ.get("SMTP_FROM_4")},
    {"host": os.environ.get("SMTP_HOST_5"), "port": int(os.environ.get("SMTP_PORT_5", 587)),
     "user": os.environ.get("SMTP_USER_5"), "pass": os.environ.get("SMTP_PASS_5"), "from": os.environ.get("SMTP_FROM_5")},
    {"host": os.environ.get("SMTP_HOST_6"), "port": int(os.environ.get("SMTP_PORT_6", 587)),
     "user": os.environ.get("SMTP_USER_6"), "pass": os.environ.get("SMTP_PASS_6"), "from": os.environ.get("SMTP_FROM_6")}
]

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# ------------------ 工具函数 ------------------
def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_jwt(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

def send_email(to_email, code):
    account = random.choice(SMTP_ACCOUNTS)  # 随机选择邮箱
    msg = MIMEText(f"你的验证码是: {code}")
    msg['Subject'] = "注册验证码"
    msg['From'] = account["from"]
    msg['To'] = to_email

    server = smtplib.SMTP(account["host"], account["port"])
    server.starttls()
    server.login(account["user"], account["pass"])
    server.send_message(msg)
    server.quit()
    print(f"[DEBUG] 用 {account['from']} 发送验证码 {code} 到 {to_email}")

# ------------------ 页面路由 ------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

# ------------------ API ------------------
@app.route("/api/send_code", methods=["POST"])
def api_send_code():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "邮箱不能为空"}), 400
    code = generate_code()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    supabase.table("email_codes").upsert({"email": email, "code": code, "expire_at": expire}).execute()
    send_email(email, code)
    return jsonify({"ok": True})

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json
    email, code, password = data.get("email"), data.get("code"), data.get("password")
    if not email or not code or not password:
        return jsonify({"error": "参数不足"}), 400
    res = supabase.table("email_codes").select("*").eq("email", email).execute()
    if not res.data or res.data[0]["code"] != code:
        return jsonify({"error": "验证码错误"}), 400
    hashed = hash_password(password)
    supabase.table("users").insert({"email": email, "password": hashed}).execute()
    return jsonify({"ok": True})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "参数不足"}), 400
    user = supabase.table("users").select("*").eq("email", email).execute().data
    if not user or not check_password(password, user[0]["password"]):
        return jsonify({"error": "账号或密码错误"}), 400
    token = create_jwt({"id": user[0]["id"], "role": user[0]["role"]})
    return jsonify({"token": token})

@app.route("/api/messages", methods=["GET", "POST"])
def api_messages():
    if request.method == "GET":
        msgs = supabase.table("messages").select("*").execute().data
        return jsonify(msgs)
    else:
        data = request.json
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        device = request.headers.get("User-Agent")
        supabase.table("messages").insert({
            "user_id": data.get("user_id"),
            "content": data.get("content"),
            "ip": ip,
            "device": device
        }).execute()
        return jsonify({"ok": True})

if __name__ == "__main__":
    app.run()
