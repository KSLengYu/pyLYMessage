# api/index.py
import os
import json
import time
import smtplib
import bcrypt
import jwt
import requests
from datetime import datetime, timedelta
from supabase import create_client

# -----------------------
# 环境变量（在 Vercel 设置）
# -----------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")  # 在 server 端使用 service role key
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
JWT_SECRET = os.environ.get("JWT_SECRET", "change_me")
SITE_URL = os.environ.get("SITE_URL", "https://your-site.vercel.app")  # 用于邮件里的回调链接

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# -----------------------
# 辅助函数
# -----------------------
def json_resp(status, obj, headers=None):
    r = {"statusCode": status, "body": json.dumps(obj)}
    if headers:
        r["headers"] = headers
    else:
        r["headers"] = {"Content-Type": "application/json"}
    return r

def generate_verification_code():
    # 更安全地使用随机数
    import random
    return ("%06d" % random.randint(0, 999999))

def send_email(to_email, subject, body_text):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP 配置未完全设置（SMTP_HOST/SMTP_USER/SMTP_PASS）")
    msg = f"From: {SMTP_USER}\r\nTo: {to_email}\r\nSubject: {subject}\r\n\r\n{body_text}"
    s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
    s.starttls()
    s.login(SMTP_USER, SMTP_PASS)
    s.sendmail(SMTP_USER, [to_email], msg.encode("utf-8"))
    s.quit()

def hash_password(plain):
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_jwt(payload, exp_minutes=60*24*30):
    payload2 = payload.copy()
    payload2["exp"] = datetime.utcnow() + timedelta(minutes=exp_minutes)
    return jwt.encode(payload2, JWT_SECRET, algorithm="HS256")

def decode_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def get_request_json(request):
    body = request.get("body")
    if not body:
        return {}
    try:
        return json.loads(body)
    except:
        return {}

def get_client_ip(headers):
    xff = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return headers.get("x-real-ip") or headers.get("remote_addr") or "unknown"

def geolocate_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=3)
        j = r.json()
        if j.get("status") == "success":
            country = j.get("country", "")
            region = j.get("regionName", "")
            city = j.get("city", "")
            return ", ".join([x for x in [country, region, city] if x])
    except Exception:
        pass
    return "未知位置"

def parse_device_from_headers(headers, body):
    if body.get("device"):
        return body.get("device")
    ua = headers.get("user-agent", "")
    ua_low = ua.lower()
    if "iphone" in ua_low:
        import re
        m = re.search(r"iphone os (\d+)_?", ua_low)
        if m:
            return f"iPhone (iOS {m.group(1)})"
        return "iPhone"
    if "ipad" in ua_low:
        return "iPad"
    if "android" in ua_low:
        return "Android"
    if "mac os x" in ua_low or "macintosh" in ua_low:
        return "Mac"
    if "windows" in ua_low:
        return "Windows PC"
    return "Unknown device"

def require_auth(request):
    headers = request.get("headers", {})
    auth = headers.get("authorization") or headers.get("Authorization")
    token = None
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ",1)[1].strip()
    else:
        cookie = headers.get("cookie") or headers.get("Cookie") or ""
        for part in cookie.split(";"):
            if part.strip().startswith("token="):
                token = part.strip().split("=",1)[1]
    if not token:
        return None
    payload = decode_jwt(token)
    if not payload:
        return None
    user_id = payload.get("user_id")
    if not user_id:
        return None
    r = supabase.table("users").select("*").eq("id", user_id).limit(1).execute()
    if r.error or len(r.data)==0:
        return None
    return r.data[0]

# -----------------------
# 主处理函数（Vercel Serverless）
# -----------------------
def handler(request, context):
    try:
        method = request.get("method", "GET")
        headers = request.get("headers", {})
        query = request.get("query", {}) or {}
        action = query.get("action") or get_request_json(request).get("action")
        body = get_request_json(request)

        # 注册（创建用户并发送邮箱验证码）
        if action == "register" and method.upper() == "POST":
            email = body.get("email", "").strip().lower()
            password = body.get("password", "")
            if not email or not password:
                return json_resp(400, {"error":"email 和 password 必须提供"})
            r = supabase.table("users").select("*").eq("email", email).execute()
            if r.data and len(r.data)>0:
                return json_resp(400, {"error":"该邮箱已注册"})
            code = generate_verification_code()
            hashed = hash_password(password)
            now = datetime.utcnow().isoformat()
            ins = supabase.table("users").insert({
                "email": email,
                "password_hash": hashed,
                "is_verified": False,
                "verification_code": code,
                "verification_sent_at": now,
                "created_at": now
            }).execute()
            if ins.error:
                return json_resp(500, {"error": str(ins.error)})
            link = f"{SITE_URL}/register.html?email={email}&code={code}"
            try:
                send_email(email, "【留言板】邮箱验证", f"你的验证码是：{code}\n或者点击链接完成验证：{link}")
            except Exception as e:
                return json_resp(500, {"error":"验证码发送失败，检查 SMTP 配置: "+str(e)})
            return json_resp(200, {"message":"注册成功，验证码已发送到邮箱，请完成验证"})

        # 邮箱验证码验证
        if action == "verify_email" and method.upper() == "POST":
            email = body.get("email", "").strip().lower()
            code = body.get("code", "")
            if not email or not code:
                return json_resp(400, {"error":"email 和 code 必须提供"})
            r = supabase.table("users").select("*").eq("email", email).limit(1).execute()
            if r.error or not r.data:
                return json_resp(404, {"error":"未找到该用户"})
            user = r.data[0]
            if user.get("is_verified"):
                return json_resp(200, {"message":"已验证"})
            if str(user.get("verification_code")) != str(code):
                return json_resp(400, {"error":"验证码不正确"})
            upd = supabase.table("users").update({"is_verified": True, "verification_code": None}).eq("id", user["id"]).execute()
            if upd.error:
                return json_resp(500, {"error": str(upd.error)})
            return json_resp(200, {"message":"验证成功"})

        # 登录
        if action == "login" and method.upper() == "POST":
            email = body.get("email", "").strip().lower()
            password = body.get("password", "")
            if not email or not password:
                return json_resp(400, {"error":"email/password 必须提供"})
            r = supabase.table("users").select("*").eq("email", email).limit(1).execute()
            if r.error or not r.data:
                return json_resp(400, {"error":"邮箱或密码错误"})
            user = r.data[0]
            hashed = user.get("password_hash")
            if not hashed or not check_password(password, hashed):
                return json_resp(400, {"error":"邮箱或密码错误"})
            if user.get("banned_until"):
                try:
                    bu = datetime.fromisoformat(user["banned_until"]) if isinstance(user["banned_until"], str) else None
                    if bu and bu > datetime.utcnow():
                        return json_resp(403, {"error": "账号被封禁至 " + str(user["banned_until"])})
                except:
                    pass
            token = create_jwt({"user_id": user["id"], "role": user.get("role", "user")}, exp_minutes=60*24*30)
            supabase.table("users").update({"last_login": datetime.utcnow().isoformat()}).eq("id", user["id"]).execute()
            headers = {
                "Set-Cookie": f"token={token}; HttpOnly; Path=/; Max-Age={60*60*24*30}",
                "Content-Type": "application/json"
            }
            return {"statusCode":200, "body": json.dumps({"message":"登录成功", "token": token}), "headers": headers}

        # 登出
        if action == "logout":
            headers = {"Set-Cookie":"token=deleted; HttpOnly; Path=/; Max-Age=0"}
            return {"statusCode":200, "body": json.dumps({"message":"已登出"}), "headers": headers}

        # 手动绑定 QQ（不做 OAuth，仅保存用户提交的 qq 信息）
        # body: { qq_number, qq_nickname, qq_avatar }
        if action == "bind_qq_manual" and method.upper()=="POST":
            user = require_auth(request)
            if not user:
                return json_resp(401, {"error":"需要登录"})
            qq_number = body.get("qq_number")
            qq_nickname = body.get("qq_nickname")
            qq_avatar = body.get("qq_avatar")
            upd = supabase.table("users").update({
                "qq_number": qq_number,
                "qq_nickname": qq_nickname,
                "qq_avatar": qq_avatar
            }).eq("id", user["id"]).execute()
            if upd.error:
                return json_resp(500, {"error": str(upd.error)})
            return json_resp(200, {"message":"绑定 QQ 信息成功"})

        # 解绑 QQ（清空字段）
        if action == "unbind_qq" and method.upper()=="POST":
            user = require_auth(request)
            if not user:
                return json_resp(401, {"error":"需要登录"})
            upd = supabase.table("users").update({
                "qq_number": None, "qq_nickname": None, "qq_avatar": None
            }).eq("id", user["id"]).execute()
            if upd.error:
                return json_resp(500, {"error": str(upd.error)})
            return json_resp(200, {"message":"已解绑 QQ"})

        # 添加留言/回复
        if action == "add_message" and method.upper()=="POST":
            text = (body.get("text") or "").strip()
            parent_id = body.get("parent_id")
            name = body.get("name")
            if not text:
                return json_resp(400, {"error":"留言内容不能为空"})
            headers = request.get("headers", {})
            ip = get_client_ip(headers)
            device = parse_device_from_headers(headers, body)
            location = geolocate_ip(ip)
            user = require_auth(request)
            user_id = None
            if user:
                user_id = user["id"]
                if user.get("banned_until"):
                    try:
                        bu = datetime.fromisoformat(user["banned_until"]) if isinstance(user["banned_until"], str) else None
                        if bu and bu > datetime.utcnow():
                            return json_resp(403, {"error":"你的账号被封禁至 "+str(user["banned_until"])})
                    except:
                        pass
            else:
                today = datetime.utcnow().date().isoformat()
                gp = supabase.table("guest_post_quota").select("*").eq("ip", ip).limit(1).execute()
                if gp.data and len(gp.data)>0:
                    rec = gp.data[0]
                    if str(rec.get("date")) != today:
                        supabase.table("guest_post_quota").upsert({"ip": ip, "date": today, "count": 1}).execute()
                    else:
                        if rec.get("count",0) >= 5:
                            return json_resp(403, {"error":"游客每天只能发布 5 条留言，请注册/登录以解除限制"})
                        else:
                            supabase.table("guest_post_quota").update({"count": rec.get("count",0)+1, "date": today}).eq("ip", ip).execute()
                else:
                    supabase.table("guest_post_quota").insert({"ip": ip, "date": today, "count": 1}).execute()
            if not name:
                if user and user.get("qq_nickname"):
                    name = user.get("qq_nickname")
                elif user and user.get("email"):
                    name = user.get("email").split("@")[0]
                else:
                    name = "游客"
            ins = supabase.table("messages").insert({
                "user_id": user_id,
                "name": name,
                "text": text,
                "parent_id": parent_id,
                "ip": ip,
                "location": location,
                "device": device,
                "created_at": datetime.utcnow().isoformat()
            }).execute()
            if ins.error:
                return json_resp(500, {"error": str(ins.error)})
            return json_resp(200, {"message":"发布成功", "id": ins.data[0]["id"]})

        # 获取留言（包含回复）
        if action == "get_messages" and method.upper() in ("GET","POST"):
            q = query or {}
            limit = int(q.get("limit", 200))
            include_deleted = (str(q.get("include_deleted","false")).lower() == "true")
            res = supabase.table("messages").select("*").order("created_at", desc=False).limit(limit).execute()
            if res.error:
                return json_resp(500, {"error": str(res.error)})
            data = res.data or []
            if not include_deleted:
                data = [d for d in data if not d.get("is_deleted", False)]
            user_ids = list({d.get("user_id") for d in data if d.get("user_id")})
            users = {}
            if user_ids:
                ur = supabase.table("users").select("id, email, qq_nickname, qq_avatar, role").in_("id", user_ids).execute()
                if not ur.error:
                    for u in ur.data:
                        users[u["id"]] = u
            for d in data:
                uid = d.get("user_id")
                if uid and users.get(uid):
                    d["user_info"] = users[uid]
            return json_resp(200, {"messages": data})

        # 删除/撤回留言（发布者可撤回；管理员可删除）
        if action == "delete_message" and method.upper()=="POST":
            user = require_auth(request)
            if not user:
                return json_resp(401, {"error":"需要登录"})
            mid = body.get("id")
            if not mid:
                return json_resp(400, {"error":"缺少 id"})
            r = supabase.table("messages").select("*").eq("id", mid).limit(1).execute()
            if r.error or not r.data:
                return json_resp(404, {"error":"未找到该留言"})
            msg = r.data[0]
            allowed = False
            if msg.get("user_id") == user["id"]:
                allowed = True
            if user.get("role") in ("manager","admin","superadmin"):
                allowed = True
            if not allowed:
                return json_resp(403, {"error":"无权限删除该留言"})
            upd = supabase.table("messages").update({"is_deleted": True}).eq("id", mid).execute()
            if upd.error:
                return json_resp(500, {"error": str(upd.error)})
            if user.get("role") in ("manager","admin","superadmin"):
                supabase.table("admin_actions").insert({
                    "admin_user_id": user["id"],
                    "action": "delete_message",
                    "target_id": mid,
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
            return json_resp(200, {"message":"删除成功"})

        # 设置角色（仅 superadmin）
        if action == "set_manager" and method.upper()=="POST":
            user = require_auth(request)
            if not user or user.get("role") != "superadmin":
                return json_resp(403, {"error":"仅超管可设置管理权限"})
            target_id = body.get("user_id")
            newrole = body.get("role")
            if newrole not in ("user","manager","admin","superadmin"):
                return json_resp(400, {"error":"role 无效"})
            upd = supabase.table("users").update({"role": newrole}).eq("id", target_id).execute()
            if upd.error:
                return json_resp(500, {"error": str(upd.error)})
            supabase.table("admin_actions").insert({
                "admin_user_id": user["id"],
                "action": "set_role",
                "target_id": target_id,
                "reason": newrole,
                "created_at": datetime.utcnow().isoformat()
            }).execute()
            return json_resp(200, {"message":"设置成功"})

        # 封禁用户（管理）
        if action == "ban_user" and method.upper()=="POST":
            user = require_auth(request)
            if not user or user.get("role") not in ("manager","admin","superadmin"):
                return json_resp(403, {"error":"需要管理员权限"})
            target_id = body.get("user_id")
            days = int(body.get("days",0))
            until = (datetime.utcnow() + timedelta(days=days)).isoformat() if days>0 else None
            upd = supabase.table("users").update({"banned_until": until}).eq("id", target_id).execute()
            if upd.error:
                return json_resp(500, {"error": str(upd.error)})
            supabase.table("admin_actions").insert({
                "admin_user_id": user["id"],
                "action": "ban_user",
                "target_id": target_id,
                "reason": body.get("reason",""),
                "created_at": datetime.utcnow().isoformat()
            }).execute()
            return json_resp(200, {"message":"封禁成功"})

        # 修改密码
        if action == "change_password" and method.upper()=="POST":
            user = require_auth(request)
            if not user:
                return json_resp(401, {"error":"请先登录"})
            old = body.get("old_password")
            new = body.get("new_password")
            if not old or not new:
                return json_resp(400, {"error":"old_password/new_password 必须提供"})
            if not check_password(old, user.get("password_hash","")):
                return json_resp(403, {"error":"旧密码错误"})
            new_h = hash_password(new)
            supabase.table("users").update({"password_hash": new_h}).eq("id", user["id"]).execute()
            return json_resp(200, {"message":"密码修改成功"})

        # 重置密码请求（发送验证码）
        if action == "reset_password_request" and method.upper()=="POST":
            email = body.get("email","").strip().lower()
            if not email:
                return json_resp(400, {"error":"email 必须提供"})
            r = supabase.table("users").select("*").eq("email", email).limit(1).execute()
            if r.error or not r.data:
                return json_resp(200, {"message":"如果该邮箱存在，我们已发送重置邮件"})
            code = generate_verification_code()
            supabase.table("users").update({"verification_code": code, "verification_sent_at": datetime.utcnow().isoformat()}).eq("email", email).execute()
            try:
                send_email(email, "【留言板】密码重置验证码", f"你的验证码是：{code}\n在 1 小时内有效。")
            except Exception as e:
                return json_resp(500, {"error":"邮件发送失败: "+str(e)})
            return json_resp(200, {"message":"如果该邮箱存在，我们已发送重置邮件"})

        # 重置密码确认
        if action == "reset_password_confirm" and method.upper()=="POST":
            email = body.get("email","").strip().lower()
            code = body.get("code")
            new_password = body.get("new_password")
            if not email or not code or not new_password:
                return json_resp(400, {"error":"email/code/new_password 必须提供"})
            r = supabase.table("users").select("*").eq("email", email).limit(1).execute()
            if r.error or not r.data:
                return json_resp(400, {"error":"无效请求"})
            user = r.data[0]
            if str(user.get("verification_code")) != str(code):
                return json_resp(400, {"error":"验证码不正确"})
            new_h = hash_password(new_password)
            supabase.table("users").update({"password_hash": new_h, "verification_code": None}).eq("id", user["id"]).execute()
            return json_resp(200, {"message":"密码已重置"})

        # 默认
        return json_resp(400, {"error":"unknown action or invalid method", "action": action, "method": method})

    except Exception as e:
        return json_resp(500, {"error": "server error: "+str(e)})
