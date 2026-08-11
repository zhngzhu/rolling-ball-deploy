#!/usr/bin/env python3
"""Game server with API for leaderboards, user data, and shop."""
import http.server
import json
import os
import random
import secrets
import shutil
import socket
import socketserver
import threading
import time
import uuid
import hashlib
import hmac
import base64
import race_server
import upstash_store
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(os.environ.get("PORT", 8080))
ADMIN_PORT = 8090  # 管理后台独立绑本机，不暴露公网（frpc 仅转发 8080）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIRECTORY = os.path.join(BASE_DIR, "rolling-ball")

# 云端持久化：设环境变量 DATA_DIR（例如 Zeabur 挂载卷 /data）后，存档写入挂载卷，
# 容器重启/重新部署都不会丢档。不设时沿用程序所在目录（本地运行行为不变）。
DATA_DIR = os.environ.get("DATA_DIR", "").strip() or BASE_DIR
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except Exception as _e:
    print(f"[init] DATA_DIR({DATA_DIR}) 不可用，回退到程序目录: {_e!r}")
    DATA_DIR = BASE_DIR

DATA_FILE = os.path.join(DATA_DIR, "game_data.json")


def _seed_data_file():
    """首次运行、本地还没有存档时，把仓库里自带的存档播种进去，避免空档。
    优先用 seed_data.json（随仓库/文件夹部署携带），兼容旧名 game_data.json。
    只要 DATA_FILE 已存在就跳过（绝不覆盖已有玩家进度）。"""
    if os.path.exists(DATA_FILE):
        return
    seed = None
    for cand in ("seed_data.json", "game_data.json"):
        p = os.path.join(BASE_DIR, cand)
        if os.path.exists(p):
            seed = p
            break
    if not seed:
        return
    try:
        import shutil
        shutil.copyfile(seed, DATA_FILE)
        print(f"[init] 已把初始存档播种到 {DATA_FILE}")
    except Exception as e:
        print(f"[init] 播种初始存档失败: {e!r}")


_seed_data_file()

# ---- Admin config ----
ADMIN_USER = "user"
RESERVED_ADMIN_NAMES = {"admin", "root", "administrator", "mod", "owner", "superuser", "system", "user"}
ADMIN_PASS_FILE = os.path.join(DATA_DIR, ".admin_password")

def _load_or_create_admin_pass():
    # 云端部署：用环境变量固定后台密码，避免每次冷启动生成新密码导致锁死
    env_pass = os.environ.get("ADMIN_PASS", "").strip()
    if env_pass:
        try:
            with open(ADMIN_PASS_FILE, "w", encoding="utf-8") as f:
                f.write(env_pass)
        except Exception:
            pass
        return env_pass
    if os.path.exists(ADMIN_PASS_FILE):
        with open(ADMIN_PASS_FILE, "r", encoding="utf-8") as f:
            pwd = f.read().strip()
            if pwd:
                return pwd
    # 首次运行且未指定密码：使用文档中约定的默认后台密码，
    # 部署方照 部署说明.md 用 user / 该密码即可登录（建议上线后改密）。
    pwd = "pc767d54"
    try:
        with open(ADMIN_PASS_FILE, "w", encoding="utf-8") as f:
            f.write(pwd)
    except Exception:
        pass
    return pwd

ADMIN_PASS = _load_or_create_admin_pass()
# Admin only accessible from local network
LOCAL_IP_PREFIXES = ("127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "::1")

# ---- Owner config ----
OWNER_NAME = "\u665a\u6674_\u670d\u4e3b"  # 晚晴_服主
OWNER_TITLE_KEY = "owner"
OWNER_CHAT_COLOR = "#3b82f6"  # blue

# ---- Chat (in-memory) ----
chat_messages = []
MAX_CHAT_MESSAGES = 100
# 单用户聊天频率限制（独立于全局 POST 限速，防被封禁账号/脚本刷屏）
CHAT_MIN_INTERVAL = 1.0     # 同一账号两条消息最小间隔（秒）
CHAT_MAX_PER_MIN = 20       # 同一账号每 60s 最多发送条数
last_chat = {}              # uid -> ts（最后发送时间）
chat_buckets = {}           # uid -> [bucket(int 分钟), count]

# ---- Rate limiting (in-memory) ----
# ip -> {"window_start": ts, "requests": count, "block_until": ts}
RATE_LIMIT_WINDOW = 60       # seconds
RATE_LIMIT_MAX_POST = 60       # POST requests per window per IP
RATE_LIMIT_MAX_GET = 120       # GET requests per window per IP
LOGIN_FAIL_WINDOW = 300      # 5 minutes
LOGIN_FAIL_MAX = 5           # failed login attempts before lockout
LOGIN_FAIL_LOCKOUT = 900     # 15 minutes lockout
REGISTRATION_PER_IP_DAY = 2  # max new accounts per IP per 24h
REGISTRATION_PER_HOUR = 10   # max new accounts globally per hour

rate_limit_store = {}
login_fail_store = {}        # key -> [timestamps]  (key 为 "name:<账号>" 或 "ip:<ip>")
registration_store = {}      # ip -> [timestamps]
hourly_registration_count = {"window_start": time.time(), "count": 0}

# ---- 写锁（串行化所有改数据请求，消除并发双花/双抽/数据损坏）----
WRITE_LOCK = threading.RLock()

# ---- 单 IP 最大并发请求数（缓解 DDoS / 意外洪峰：防单 IP 撑满连接与线程）----
# 取值说明：浏览器对同 host 约开 6 条 HTTP/1.1 连接，正常玩家同时在线请求远不到此数；
# 64 给足余量避免误伤，同时能在单 IP 疯狂建连/洪泛时直接 429 拒绝。
MAX_CONCURRENT_PER_IP = 64
_conn_per_ip = {}             # ip -> 当前在途请求数
_conn_lock = threading.Lock()

# 响应写出超时（秒）：防客户端断开/极慢导致 send_json 在 wfile.write 上无限阻塞，
# 进而长期占用 _conn_per_ip 并发名额（名额在请求 finally 中释放，阻塞则无法释放）。
# 仅作用于 JSON 接口响应（视频/静态流不走 send_json，不受影响）。
RESP_SEND_TIMEOUT = 10

# ---- 后台暴力破解防护 ----
ADMIN_FAIL_WINDOW = 900      # 15 分钟内
ADMIN_FAIL_MAX = 5           # 失败 5 次封锁
ADMIN_FAIL_LOCKOUT = 1800    # 封锁 30 分钟
ADMIN_RATE_WINDOW = 60       # 秒
ADMIN_RATE_MAX = 60          # 后台每分钟最多 60 请求
admin_fail_store = {}        # ip -> [ts]
admin_rate_store = {}        # ip -> {"bucket","count","block_until"}

# ---- 结算防刷 ----
SETTLE_COOLDOWN = 2          # 同一账号两次结算最小间隔（秒），防脚本连刷/重放
GAME_COIN_CAP_PER_LEVEL = 3000   # 单局金币增量上限 = 最高关 × 该值
# 经济上限封顶：max_level 可被 /api/level/up 无凭证泵高，故单局/窗口上限不再随 max_level 无限放大，
# 而是 clamp 到 HARD_CAP_LEVEL。实际玩家 max_level 最高仅 12（2026-07-28 统计），100 留足余量且不影响正常收益。
HARD_CAP_LEVEL = 100
last_settle = {}             # uid -> ts
# 累计增速上限（防“冷却期后仍反复上报同一局”无限刷金币/总分）：
# 每个时间窗口内 coins/score 的累计增量不超过该值（窗口大小见下）。
GAME_ACCRUAL_WINDOW = 60     # 秒
accrual_window = {}          # uid -> {"coins": [bucket, used], "score": [bucket, used]}

# ---- 密码强度（防弱口令冒名）----
MIN_PASSWORD_LEN = 6
TRIVIAL_PASSWORDS = {
    "123456", "12345678", "123456789", "password", "111111", "000000",
    "123", "1", "qwerty", "abc123", "1234567", "666666", "888888",
}

# ---- Captcha store (in-memory) ----
# captcha_id -> {"answer": str, "created_at": ts}
CAPTCHA_TTL = 300            # 5 minutes
captcha_store = {}

import re

BLOCKED_PATTERNS = [
    re.compile(r'<\?php', re.I),       # PHP tags
    re.compile(r'<\?', re.I),           # Short PHP tags
    re.compile(r'<%', re.I),            # ASP tags
    re.compile(r'<script', re.I),       # Script tags
    re.compile(r'</script>', re.I),
    re.compile(r'<html', re.I),
    re.compile(r'<body', re.I),
    re.compile(r'<iframe', re.I),
    re.compile(r'<img', re.I),
    re.compile(r'<svg', re.I),
    re.compile(r'<object', re.I),
    re.compile(r'<embed', re.I),
    re.compile(r'<link', re.I),         # Link tags (CSS injection)
    re.compile(r'<meta', re.I),         # Meta tags
    re.compile(r'<style', re.I),        # Style tags
    re.compile(r'<base', re.I),         # Base tags
    re.compile(r'<form', re.I),         # Form tags
    re.compile(r'<input', re.I),        # Input tags
    re.compile(r'javascript:', re.I),   # JS protocol
    re.compile(r'vbscript:', re.I),     # VBScript protocol
    re.compile(r'data:text/html', re.I),# Data URI HTML
    re.compile(r'on\w+\s*=', re.I),     # Event handlers like onclick=
    re.compile(r'eval\s*\(', re.I),     # eval()
    re.compile(r'exec\s*\(', re.I),     # exec()
    re.compile(r'system\s*\(', re.I),   # system()
    re.compile(r'passthru\s*\(', re.I),
    re.compile(r'shell_exec\s*\(', re.I),
    re.compile(r'proc_open\s*\(', re.I),
    re.compile(r'popen\s*\(', re.I),
    re.compile(r'assert\s*\(', re.I),   # PHP assert RCE
    re.compile(r'create_function\s*\(', re.I),
    re.compile(r'call_user_func', re.I),
    re.compile(r'base64_decode\s*\(', re.I),
    re.compile(r'file_get_contents\s*\(', re.I),
    re.compile(r'file_put_contents\s*\(', re.I),
    re.compile(r'fopen\s*\(', re.I),
    re.compile(r'fwrite\s*\(', re.I),
    re.compile(r'readfile\s*\(', re.I),
    re.compile(r'include\s*\(', re.I),  # PHP include
    re.compile(r'require\s*\(', re.I),  # PHP/Node require
    re.compile(r'child_process', re.I), # Node.js RCE
    re.compile(r'__construct', re.I),
    re.compile(r'__destruct', re.I),
    re.compile(r'document\.cookie', re.I),  # Cookie theft
    re.compile(r'document\.write', re.I),
    re.compile(r'document\.location', re.I),
    re.compile(r'window\.location', re.I),
    re.compile(r'window\.open', re.I),
    re.compile(r'XMLHttpRequest', re.I),
    re.compile(r'fetch\s*\(', re.I),    # Fetch API
    re.compile(r'localStorage', re.I),
    re.compile(r'sessionStorage', re.I),
    re.compile(r'navigator\.', re.I),   # Browser fingerprinting
    re.compile(r'\.innerHtml', re.I),   # DOM manipulation
    re.compile(r'\.outerHtml', re.I),
    re.compile(r'union\s+select', re.I),  # SQL injection
    re.compile(r'drop\s+table', re.I),
    re.compile(r'insert\s+into', re.I),
    re.compile(r'delete\s+from', re.I),
    re.compile(r'update\s+.*set', re.I),
    re.compile(r'load_file\s*\(', re.I),  # MySQL file read
    re.compile(r'into\s+outfile', re.I),  # MySQL file write
    re.compile(r'sleep\s*\(\s*\d+\s*\)', re.I),  # SQL sleep (blind injection)
    re.compile(r'benchmark\s*\(', re.I),  # SQL benchmark
    re.compile(r'information_schema', re.I),  # SQL schema enumeration
]

# Username: only allow letters, digits, Chinese chars, underscore, hyphen
USERNAME_RE = re.compile(r'^[\w\u4e00-\u9fff\-]{1,12}$')
# Email: basic format validation
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
# Hex color: #rgb or #rrggbb only (prevents CSS/JS injection via style attr)
HEX_COLOR_RE = re.compile(r'^#[0-9a-fA-F]{3,6}$')

def sanitize_chat_color(color):
    """Validate chat_color is a safe hex color; return default if invalid."""
    if not isinstance(color, str) or not HEX_COLOR_RE.match(color):
        return "#e2e8f0"
    return color

def sanitize_input(text, is_username=False):
    """Return cleaned text or raise ValueError if blocked content detected."""
    if not isinstance(text, str):
        raise ValueError("invalid input")
    text = text.strip()
    for pat in BLOCKED_PATTERNS:
        if pat.search(text):
            raise ValueError("blocked content")
    # Strip any remaining HTML-like tags
    text = re.sub(r'<[^>]*>', '', text)
    if is_username:
        if not USERNAME_RE.match(text):
            raise ValueError("invalid username")
    return text


def sanitize_password(text):
    """密码专用清理：仅做最小规范化——去首尾空白、剔除 ASCII 控制字符（\\x00-\\x1f、\\x7f），
    但**不剥离 HTML 标签**。原因：密码仅以 PBKDF2 哈希存储、绝不回显，剥离 < > 等字符会
    静默削弱口令熵且用户无感知（如 a<b>c 被改成 abc）；内容关键字过滤（BLOCKED_PATTERNS）
    也不适用密码，否则会泄漏哪些词被禁。"""
    if not isinstance(text, str):
        raise ValueError("invalid password")
    text = text.strip()
    text = "".join(ch for ch in text if ch == " " or not (ord(ch) < 32 or ord(ch) == 127))
    return text


def get_user_safe(user, name):
    """Return user data without password or IP info, with owner overrides applied.
    Owner is detected by UID (stable across rename) OR by the canonical name."""
    safe = {k: v for k, v in user.items() if k not in ("password", "reg_ip", "last_ip")}
    safe["name"] = name  # 当前显示名（改名后此处即新名）
    safe.setdefault("uid", "")
    safe.setdefault("title", "newbie")
    safe.setdefault("owned_titles", ["none", "newbie"])
    safe.setdefault("chat_color", "#e2e8f0")
    safe["inscriptions"] = user.get("inscriptions", []) if isinstance(user.get("inscriptions"), list) else []
    safe["equipped"] = user.get("equipped", []) if isinstance(user.get("equipped"), list) else []
    # Apply owner overrides (by uid first, so renaming keeps perks)
    is_owner = (name == OWNER_NAME) or (OWNER_UID and user.get("uid") == OWNER_UID)
    if is_owner:
        safe["title"] = OWNER_TITLE_KEY
        safe["chat_color"] = OWNER_CHAT_COLOR
        if "owner" not in safe["owned_titles"]:
            safe["owned_titles"] = safe["owned_titles"] + ["owner"]
    return safe


def load_data():
    # 优先从 Upstash 读取（云端唯一可靠的状态源）
    try:
        mem = upstash_store.ups_get(upstash_store.MEM_KEY)
        if mem is not None and isinstance(mem, dict):
            mem.setdefault("users", {})
            mem.setdefault("leaderboards", {"level": [], "coins": [], "score": []})
            mem.setdefault("bans", {"accounts": [], "ips": [], "uids": []})
            return mem
    except Exception as e:
        print(f"[load_data] upstash 读取失败，回退本地: {e!r}")
    # 回退：本地 game_data.json
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "users": {},
        "leaderboards": {"level": [], "coins": [], "score": []},
        "bans": {"accounts": [], "ips": [], "uids": []},
    }


def _save_local(data):
    """原子写本地文件：先写临时文件再 os.replace，作为 Upstash 的缓存/备份。"""
    import tempfile
    dir_name = os.path.dirname(DATA_FILE) or "."
    fd, tmp = tempfile.mkstemp(dir=dir_name, prefix=".game_data.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, DATA_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_data(data):
    """落盘到本地（缓存）+ 持久化到 Upstash（云端真源）。Upstash 不可用时不阻塞。"""
    try:
        _save_local(data)
    except Exception as e:
        print(f"[save_data] 本地写失败: {e!r}")
    try:
        upstash_store.ups_set(upstash_store.MEM_KEY, data)
    except Exception as e:
        print(f"[save_data] upstash 写失败: {e!r}")


game_data = load_data()


def _upsert_leaderboard(name, key, value):
    """把某用户的指定榜单条目更新为 value（不存在则新增），重排并截断前 50。
    与结算接口保持一致，供后台修改用户数据后让排行榜即时同步。"""
    board = game_data["leaderboards"].get(key, [])
    board = [e for e in board if e.get("name") != name]
    board.append({"name": name, "value": value})
    board.sort(key=lambda x: x["value"], reverse=True)
    game_data["leaderboards"][key] = board[:50]


# ---- UID: stable per-account identity (survives rename) ----
def gen_uid():
    """Generate a unique, URL-safe uid like 'u1a2b3c4d5e6'."""
    return "u" + uuid.uuid4().hex[:11]


def find_user_by_uid(uid):
    if not uid:
        return None
    for u in game_data["users"].values():
        if u.get("uid") == uid:
            return u
    return None


def resolve_user(name, uid):
    """Return (user_dict, resolved_display_name) or (None, None).
    Prefer uid (stable); fall back to name."""
    if uid:
        user = find_user_by_uid(uid)
        if user is not None:
            # 用 uid 值定位当前显示名（不依赖对象身份，避免反序列化副本问题）
            for k, v in game_data["users"].items():
                if v.get("uid") == uid:
                    return user, k
            return user, None
    if name:
        user = game_data["users"].get(name)
        if user is not None:
            return user, name
    return None, None


def _backfill_uids():
    """Ensure every user has a uid; persist owner uid for stable owner perks."""
    changed = False
    for u in game_data["users"].values():
        if not u.get("uid"):
            u["uid"] = gen_uid()
            changed = True
    if "owner_uid" not in game_data:
        for _n, _u in game_data["users"].items():
            if _n == OWNER_NAME:
                game_data["owner_uid"] = _u.get("uid")
                changed = True
                break
    if changed:
        save_data(game_data)


_backfill_uids()

def _backfill_max_level():
    """确保每用户有 max_level（历史最高到达关卡）。初始取 max(排行榜关卡, 存档关卡, 1)。"""
    changed = False
    lb_level = {e["name"]: e["value"] for e in game_data["leaderboards"].get("level", [])}
    for name, u in game_data["users"].items():
        if "max_level" not in u:
            save_lvl = (u.get("save") or {}).get("level", 0) or 0
            lb_lvl = lb_level.get(name, 0)
            u["max_level"] = max(save_lvl, lb_lvl, 1)
            changed = True
    if changed:
        save_data(game_data)

_backfill_max_level()
# Stable owner identity (by uid, survives rename)
OWNER_UID = game_data.get("owner_uid")


# ---- Announcement & Ban config (persisted) ----
def _backfill_config():
    """Ensure announcement + bans structures exist in game_data."""
    changed = False
    if "announcement" not in game_data:
        game_data["announcement"] = {
            "title": "欢迎来到滚动的小球",
            "text": "如有疑问请联系服主！",
            "contact": "QQ：2917149421",
            "enabled": True,
        }
        changed = True
    if "bans" not in game_data:
        game_data["bans"] = {"accounts": [], "ips": [], "uids": []}
        changed = True
    for k in ("accounts", "ips", "uids"):
        if k not in game_data["bans"]:
            game_data["bans"][k] = []
            changed = True
    if changed:
        save_data(game_data)

_backfill_config()

def _migrate_inscriptions():
    """铭文系统迁移：旧版 inscriptions 为 {id: count} 字典 → 新版 [{id, level}] 列表；
    并补齐 equipped 字段。可重复利用、装备制、合成升级的数据结构基础。"""
    changed = False
    for u in game_data["users"].values():
        ins = u.get("inscriptions")
        if isinstance(ins, dict):
            new_list = []
            for k, v in ins.items():
                try:
                    cnt = int(v)
                except (TypeError, ValueError):
                    cnt = 0
                for _ in range(cnt):
                    new_list.append({"id": k, "level": 1})
            u["inscriptions"] = new_list
            changed = True
        elif not isinstance(ins, list):
            u["inscriptions"] = []
            changed = True
        else:
            fixed = []
            for it in ins:
                if isinstance(it, dict) and it.get("id"):
                    it.setdefault("level", 1)
                    fixed.append(it)
            if len(fixed) != len(ins):
                u["inscriptions"] = fixed
                changed = True
        eq = u.get("equipped")
        if not isinstance(eq, list):
            u["equipped"] = []
            changed = True
        else:
            ok = [e for e in eq if isinstance(e, dict) and e.get("id")]
            if len(ok) != len(eq):
                u["equipped"] = ok
                changed = True
    if changed:
        save_data(game_data)

_migrate_inscriptions()


def is_banned(name=None, uid=None, ip=None):
    """Return (banned, ban_type, reason, expires).
    expires is a unix timestamp or None (permanent). Expired bans count as not banned."""
    bans = game_data.get("bans", {"accounts": [], "ips": [], "uids": []})
    now = int(time.time())

    def _check(lst, key):
        for e in lst:
            if isinstance(e, dict):
                if e.get("value") == key:
                    exp = e.get("expires")
                    if exp and now >= exp:
                        return True, e.get("reason", "") or "", exp  # matched but expired
                    return True, e.get("reason", "") or "", exp
            elif e == key:
                return True, "", None
        return False, "", None

    for key, val, label in (("ips", ip, "IP"), ("accounts", name, "账号"), ("uids", uid, "机器")):
        if val:
            ok, reason, exp = _check(bans.get(key, []), val)
            if ok:
                if exp and now >= exp:
                    return False, "", "", None  # expired -> not banned
                return True, label, (reason or _default_reason(label)), exp
    return False, "", "", None


def _default_reason(label):
    return {
        "IP": "该网络已被封禁，请联系服主",
        "账号": "该账号已被封禁，请联系服主",
        "机器": "该设备已被封禁，请联系服主",
    }.get(label, "您已被封禁，请联系服主")


def human_duration(sec):
    if sec is None:
        return "永久"
    if sec <= 0:
        return "0"
    if sec < 60:
        return f"{sec}秒"
    if sec < 3600:
        return f"{sec // 60}分钟"
    if sec < 86400:
        return f"{sec // 3600}小时"
    if sec < 86400 * 30:
        return f"{sec // 86400}天"
    if sec < 86400 * 365:
        return f"{sec // (86400 * 30)}个月"
    return f"{sec // (86400 * 365)}年"


def format_ban(btype, reason, expires):
    msg = f"您已被封禁（{btype}）"
    if reason:
        msg += f"：{reason}"
    if expires:
        left = expires - int(time.time())
        if left > 0:
            msg += f"，{human_duration(left)}后自动解封"
    return msg


def cleanup_expired_bans():
    """Remove bans whose expires timestamp has passed. Returns True if anything changed."""
    bans = game_data.get("bans")
    if not bans:
        return False
    now = int(time.time())
    changed = False
    for key in ("accounts", "ips", "uids"):
        lst = bans.get(key, [])
        new_lst = [e for e in lst
                   if not (isinstance(e, dict) and e.get("expires") and now >= e["expires"])]
        if len(new_lst) != len(lst):
            bans[key] = new_lst
            changed = True
    if changed:
        save_data(game_data)
    return changed


def ban_cleaner():
    """Background thread: purge expired bans every 60s so auto-unban works without traffic."""
    while True:
        time.sleep(60)
        try:
            cleanup_expired_bans()
        except Exception:
            pass


# ---- 限流/反作弊字典后台清理：防止长期运行内存泄漏 ----
# 以下字典（last_chat / chat_buckets / last_settle / accrual_window / last_level_up /
# rate_limit_store）均按 uid 或 ip|subkey 累积，原先没有任何过期删除逻辑，
# 公网长期运行会无限增长。每 10 分钟清理一次超过 RATE_LIMIT_TTL 未活跃的条目。
RATE_LIMIT_TTL = 7 * 24 * 3600  # 7 天无活跃则回收

def _safe_prune_ts(d, now):
    """删除 d[uid]=时间戳 中距今 > TTL 的条目。先快照再删除，避免与业务线程迭代冲突。"""
    try:
        snap = dict(d)
    except RuntimeError:
        return  # 迭代期间字典被并发修改（极少见），跳过本次，下次重试
    for k, v in snap.items():
        if isinstance(v, (int, float)) and (now - v) > RATE_LIMIT_TTL:
            d.pop(k, None)

def _bucket_of(v):
    """从限流条目 value 中提取最新时间桶，兼容三种结构：
      - list/tuple 型（chat_buckets=[bucket,count]）
      - 含 bucket 字段的 dict 型（rate_limit_store={"bucket":...,...}）
      - 嵌套 list 子项的 dict 型（accrual_window={"coins":[b,u],"score":[b,u]}），
        取内部最新活跃桶。"""
    try:
        if isinstance(v, (list, tuple)) and len(v) >= 1:
            return int(v[0])
        if isinstance(v, dict):
            if "bucket" in v and isinstance(v["bucket"], (int, float)):
                return int(v["bucket"])
            best = None
            for sub in v.values():
                if isinstance(sub, (list, tuple)) and len(sub) >= 1:
                    b = int(sub[0])
                    if best is None or b > best:
                        best = b
            return best
    except Exception:
        pass
    return None

def _safe_prune_bucket(d, now, window):
    """删除 bucket 型字典中过于陈旧的条目（兼容 list 与嵌套 dict 两种 value 结构）。"""
    try:
        snap = dict(d)
    except RuntimeError:
        return
    cur = int(now // window)
    max_age = int(RATE_LIMIT_TTL / window) + 2
    for k, v in snap.items():
        b = _bucket_of(v)
        if b is None or (cur - b) > max_age:
            d.pop(k, None)

def rate_limit_cleaner():
    """后台守护线程：回收各限流/反作弊字典的过期条目，杜绝内存泄漏。"""
    while True:
        time.sleep(600)
        try:
            now = time.time()
            _safe_prune_ts(last_chat, now)
            _safe_prune_ts(last_settle, now)
            _safe_prune_ts(last_level_up, now)
            _safe_prune_bucket(chat_buckets, now, 60)
            _safe_prune_bucket(accrual_window, now, GAME_ACCRUAL_WINDOW)
            _safe_prune_bucket(rate_limit_store, now, RATE_LIMIT_WINDOW)
        except Exception as e:
            print("[rate_limit_cleaner error]", repr(e))


# ---- Anti-cheat: rate limiter ----
last_level_up = {}  # uid -> timestamp of last successful level-up
LEVEL_UP_COOLDOWN = 5  # seconds between reports per account

# ---- Shop catalog (mirrors front-end prices) ----
SHOP_ITEMS = {
    "ball": {
        "default": 0, "flame": 50, "forest": 80, "gold": 150, "purple": 200, "rainbow": 300,
    },
    "bg": {
        "default": 0, "sunset": 100, "ocean": 120, "night": 200, "sakura": 150,
    },
    "title": {
        "none": 0, "newbie": 0, "pro": 100, "lucky": 150, "grinder": 180,
        "rich": 200, "hermit": 250, "legend": 500, "owner": -1,
    },
}

# ---- Lottery (抽奖) config ----
LOTTERY_COST = 100
# 奖池：weight 为相对权重（总和任意）。稀有铭文（守护/黄金/智慧/幸运）总权重高于传说（回生/疾风/烈焰/寒冰），
# 符合"稀有更常见"设定；具体：传说合计 20、稀有合计 38、普通(金币/谢谢)合计 42（总和 100）。
# type: inscription(铭文, 入库) / coins(返金币) / none(谢谢参与)
LOTTERY_POOL = [
    {"id": "huisheng", "name": "回生卷轴", "type": "inscription", "rarity": "epic",
     "weight": 6,
     "desc": "史诗铭文：装备后死亡原地复活，重生次数=铭文等级（Lv.1 一次，Lv.3 三次），可重复利用"},
    {"id": "gale", "name": "疾风铭文", "type": "inscription", "rarity": "epic",
     "weight": 6,
     "desc": "史诗铭文：局内手动激活，约5秒内球操控更灵敏、障碍减速"},
    {"id": "flame", "name": "烈焰铭文", "type": "inscription", "rarity": "epic",
     "weight": 4,
     "desc": "史诗铭文：局内手动激活，约3秒烈焰冲刺，无敌撞穿障碍"},
    {"id": "frost", "name": "寒冰铭文", "type": "inscription", "rarity": "epic",
     "weight": 4,
     "desc": "史诗铭文：局内手动激活，约3秒冰封领域，障碍近乎停滞、球更可控"},
    {"id": "guard", "name": "守护铭文", "type": "inscription", "rarity": "rare",
     "weight": 10,
     "desc": "稀有铭文：局内手动激活，约4秒无敌护盾"},
    {"id": "gold", "name": "黄金铭文", "type": "inscription", "rarity": "rare",
     "weight": 10,
     "desc": "稀有铭文（结算加成已移除）"},
    {"id": "wisdom", "name": "智慧铭文", "type": "inscription", "rarity": "rare",
     "weight": 9,
     "desc": "稀有铭文（结算加成已移除）"},
    {"id": "luck", "name": "幸运铭文", "type": "inscription", "rarity": "rare",
     "weight": 9,
     "desc": "稀有铭文（结算/抽奖加成均已移除）"},
    {"id": "coins50", "name": "金币+50", "type": "coins", "amount": 50, "rarity": "common", "weight": 18},
    {"id": "coins20", "name": "金币+20", "type": "coins", "amount": 20, "rarity": "common", "weight": 19},
    {"id": "none", "name": "谢谢参与", "type": "none", "rarity": "common", "weight": 5},
]
LOTTERY_TOTAL_WEIGHT = sum(item["weight"] for item in LOTTERY_POOL)


def _lottery_roll(user):
    """执行一次加权抽奖，应用该用户的 drop_rate 倍率（后台恶搞用）。
    drop_rate 默认 1.0；>1 提升好东西概率，<1 增加「谢谢参与」概率。
    仅对 type=='none'（谢谢参与）以外的项目乘以倍率，谢谢参与权重不变。"""
    items = LOTTERY_POOL
    dr = user.get("drop_rate", 1.0)
    try:
        dr = float(dr)
    except (TypeError, ValueError):
        dr = 1.0
    if dr < 0:
        dr = 0.0
    weights = [it["weight"] if it.get("type") == "none" else it["weight"] * dr for it in items]
    total = sum(weights)
    if total <= 0:
        return items[-1]
    roll = random.uniform(0, total)
    acc = 0.0
    chosen = items[-1]
    for it, w in zip(items, weights):
        acc += w
        if roll <= acc:
            chosen = it
            break
    return chosen


def clean_ip(ip):
    """Normalize IP; treat loopback/IPv6 mapped as 127.0.0.1."""
    ip = (ip or "").strip()
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def _now_bucket(ts=None):
    return int((ts or time.time()) // RATE_LIMIT_WINDOW)


def check_rate_limit(ip, is_post=True, subkey=""):
    """Return (allowed, retry_after_seconds) for a given IP.
    subkey（通常为账号 uid/name）使已登录请求的限流按账号维度隔离，
    避免隧道下全员共用 127.0.0.1 桶被单一滥用者拖垮（可用性 DoS 缓解）。"""
    ip = clean_ip(ip)
    key = (ip + "|" + subkey) if subkey else ip
    now = time.time()
    bucket = _now_bucket(now)
    limit = RATE_LIMIT_MAX_POST if is_post else RATE_LIMIT_MAX_GET
    entry = rate_limit_store.get(key)
    if entry is None or entry["bucket"] != bucket:
        entry = {"bucket": bucket, "count": 0, "block_until": 0}
        rate_limit_store[key] = entry
    if now < entry["block_until"]:
        return False, int(entry["block_until"] - now) + 1
    entry["count"] += 1
    if entry["count"] > limit:
        block_until = now + RATE_LIMIT_WINDOW
        entry["block_until"] = block_until
        return False, int(block_until - now) + 1
    return True, 0


def _accrual_cap(uid, kind, proposed, window, ceiling):
    """Return how much of `proposed` gain is allowed this window.

    Caps total accrual of `kind` ("coins"/"score") to `ceiling` per `window`
    seconds, so a cheater replaying the same settlement every cooldown can no
    longer inflate coins/score without bound (only at a legit-style rate)."""
    if proposed <= 0:
        return 0
    now = time.time()
    b = int(now // window)
    track = accrual_window.get(uid)
    if track is None:
        track = accrual_window[uid] = {}
    if track.get(kind, [0, 0])[0] != b:
        track[kind] = [b, 0]
    bucket, used = track[kind]
    remaining = max(0, ceiling - used)
    allowed = min(proposed, remaining)
    track[kind][1] = used + allowed
    return allowed


def check_chat_rate(uid):
    """Return (allowed, retry_after_seconds) for a single user's chat sending.

    与全局 POST 限速互补：即使隧道下全员共用 127.0.0.1 桶，也能按账号维度
    限制刷屏（最小间隔 + 每分钟上限）。未登录（无 uid）的请求不受此限，
    但会被全局 POST 限速与下方密码校验挡住。"""
    if not uid:
        return True, 0
    now = time.time()
    last = last_chat.get(uid, 0)
    if now - last < CHAT_MIN_INTERVAL:
        return False, int(CHAT_MIN_INTERVAL - (now - last)) + 1
    b = int(now // 60)
    ent = chat_buckets.get(uid)
    if ent is None or ent[0] != b:
        ent = chat_buckets[uid] = [b, 0]
    if ent[1] >= CHAT_MAX_PER_MIN:
        return False, int((b + 1) * 60 - now) + 1
    ent[1] += 1
    last_chat[uid] = now
    return True, 0


def record_login_failure(ip, name=None):
    """记录一次登录失败。优先按账号名维度计数，避免隧道下单一 IP 被锁后全员无法登录（可用性 DoS）。"""
    ip = clean_ip(ip)
    key = ("name:" + name) if name else ("ip:" + ip)
    now = time.time()
    window_start = now - LOGIN_FAIL_WINDOW
    attempts = login_fail_store.get(key, [])
    attempts = [t for t in attempts if t > window_start]
    attempts.append(now)
    login_fail_store[key] = attempts
    return len(attempts)


def check_login_lockout(ip, name=None):
    """Return (locked, retry_after_seconds). 按账号名（优先）或 IP 维度判断。"""
    ip = clean_ip(ip)
    key = ("name:" + name) if name else ("ip:" + ip)
    now = time.time()
    entry = login_fail_store.get(key, [])
    window_start = now - LOGIN_FAIL_WINDOW
    recent = [t for t in entry if t > window_start]
    if len(recent) >= LOGIN_FAIL_MAX:
        last_fail = max(recent)
        lockout_end = last_fail + LOGIN_FAIL_LOCKOUT
        if now < lockout_end:
            return True, int(lockout_end - now) + 1
    return False, 0


def record_registration(ip):
    ip = clean_ip(ip)
    now = time.time()
    global hourly_registration_count
    if now - hourly_registration_count["window_start"] >= 3600:
        hourly_registration_count = {"window_start": now, "count": 0}
    hourly_registration_count["count"] += 1
    window_start = now - 86400
    regs = registration_store.get(ip, [])
    regs = [t for t in regs if t > window_start]
    regs.append(now)
    registration_store[ip] = regs


def check_registration_limit(ip):
    """Return (allowed, reason)."""
    ip = clean_ip(ip)
    now = time.time()
    # global hourly cap
    global hourly_registration_count
    if now - hourly_registration_count["window_start"] >= 3600:
        hourly_registration_count = {"window_start": now, "count": 0}
    if hourly_registration_count["count"] >= REGISTRATION_PER_HOUR:
        return False, "本小时注册人数已达上限，请稍后再试"
    # per-IP daily cap
    regs = registration_store.get(ip, [])
    day_start = now - 86400
    if len([t for t in regs if t > day_start]) >= REGISTRATION_PER_IP_DAY:
        return False, "该网络今日注册次数已达上限"
    return True, ""


def _strong_password(p):
    """密码强度校验：长度达标且非常见弱口令。"""
    if not isinstance(p, str) or len(p) < MIN_PASSWORD_LEN:
        return False
    if p in TRIVIAL_PASSWORDS:
        return False
    return True


# ---- 密码哈希（PBKDF2-HMAC-SHA256）----
# 存储格式：$pbkdf2$<iter>$<salt_b64>$<hash_b64>
# 设计要点：
#  - 服务端落盘存哈希，明文密码只在登录/改密时由客户端随包上传、不落库；
#  - _verify_password 同时兼容「已是哈希(新)」与「旧明文(迁移前)」两种 stored 值；
#  - 旧明文账号在 /api/login 首次成功登录时自动升级为哈希（见登录分支）；
#  - 明文比较用 hmac.compare_digest 做恒定时间，避免计时侧信道。
PBKDF2_ITER = 100000
PBKDF2_HASH = "sha256"

def _hash_password(p):
    """把明文密码转成 $pbkdf2$... 格式。空值原样返回（无密码账号不应被哈希）。"""
    if not isinstance(p, str) or p == "":
        return p
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, p.encode("utf-8"), salt, PBKDF2_ITER)
    return "$pbkdf2$%d$%s$%s" % (
        PBKDF2_ITER,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )

def _is_pwd_hashed(stored):
    return isinstance(stored, str) and stored.startswith("$pbkdf2$")

def _verify_password(stored, provided):
    """校验密码。stored 可能是哈希(新)或明文(旧)；provided 永远是客户端上传的明文。"""
    if not isinstance(stored, str) or not isinstance(provided, str):
        return False
    if _is_pwd_hashed(stored):
        try:
            parts = stored.split("$")
            if len(parts) != 5:
                return False
            iterations = int(parts[2])
            salt = base64.b64decode(parts[3])
            expected = base64.b64decode(parts[4])
        except Exception:
            return False
        dk = hashlib.pbkdf2_hmac(PBKDF2_HASH, provided.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    # 旧明文：恒定时间比较
    return hmac.compare_digest(stored.encode("utf-8"), provided.encode("utf-8"))


def check_admin_rate_limit(ip):
    """后台接口独立限速：防扫描/爆破（与游戏接口限流桶隔离）。"""
    ip = clean_ip(ip)
    now = time.time()
    bucket = _now_bucket(now)
    entry = admin_rate_store.get(ip)
    if entry is None or entry["bucket"] != bucket:
        entry = {"bucket": bucket, "count": 0, "block_until": 0}
        admin_rate_store[ip] = entry
    if now < entry["block_until"]:
        return False, int(entry["block_until"] - now) + 1
    entry["count"] += 1
    if entry["count"] > ADMIN_RATE_MAX:
        block_until = now + ADMIN_RATE_WINDOW
        entry["block_until"] = block_until
        return False, int(block_until - now) + 1
    return True, 0


def record_admin_failure(ip):
    ip = clean_ip(ip)
    now = time.time()
    window_start = now - ADMIN_FAIL_WINDOW
    attempts = admin_fail_store.get(ip, [])
    attempts = [t for t in attempts if t > window_start]
    attempts.append(now)
    admin_fail_store[ip] = attempts
    return len(attempts)


def check_admin_lockout(ip):
    """Return (locked, retry_after_seconds) for admin auth failures."""
    ip = clean_ip(ip)
    now = time.time()
    attempts = admin_fail_store.get(ip, [])
    window_start = now - ADMIN_FAIL_WINDOW
    recent = [t for t in attempts if t > window_start]
    if len(recent) >= ADMIN_FAIL_MAX:
        last_fail = max(recent)
        lockout_end = last_fail + ADMIN_FAIL_LOCKOUT
        if now < lockout_end:
            return True, int(lockout_end - now) + 1
    return False, 0


def generate_captcha_svg():
    """Generate a simple 4-digit numeric captcha SVG image. Returns (captcha_id, svg_text)."""
    code = "".join(random.choice("0123456789") for _ in range(4))
    cid = secrets.token_urlsafe(16)
    captcha_store[cid] = {"answer": code, "created_at": time.time()}
    # Cleanup old captchas occasionally
    now = time.time()
    expired = [k for k, v in captcha_store.items() if now - v["created_at"] > CAPTCHA_TTL]
    for k in expired:
        captcha_store.pop(k, None)

    # Simple SVG with noise lines and distorted text
    width, height = 120, 40
    lines = []
    for _ in range(5):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#94a3b8" stroke-width="1"/>')
    chars = []
    for i, ch in enumerate(code):
        x = 20 + i * 24 + random.randint(-3, 3)
        y = 28 + random.randint(-5, 5)
        rot = random.randint(-20, 20)
        color = random.choice(["#334155", "#1e293b", "#475569", "#0f172a"])
        chars.append(f'<text x="{x}" y="{y}" font-size="24" fill="{color}" transform="rotate({rot} {x} {y})">{ch}</text>')
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<rect width="100%" height="100%" fill="#f1f5f9"/>'
        f'{"".join(lines)}'
        f'{"".join(chars)}'
        f'</svg>'
    )
    return cid, svg


def verify_captcha(captcha_id, answer):
    if not captcha_id or not answer:
        return False
    entry = captcha_store.get(captcha_id)
    if not entry:
        return False
    if time.time() - entry["created_at"] > CAPTCHA_TTL:
        captcha_store.pop(captcha_id, None)
        return False
    if answer.upper() == entry["answer"].upper():
        captcha_store.pop(captcha_id, None)
        return True
    return False


def is_owned_key(user, item_type, key):
    if item_type == "ball":
        return key in user.get("owned_ball_skins", [])
    if item_type == "bg":
        return key in user.get("owned_bg_skins", [])
    if item_type == "title":
        return key in user.get("owned_titles", [])
    return False


def grant_item(user, item_type, key):
    if item_type == "ball":
        user.setdefault("owned_ball_skins", ["default"])
        if key not in user["owned_ball_skins"]:
            user["owned_ball_skins"].append(key)
        user["ball_skin"] = key
    elif item_type == "bg":
        user.setdefault("owned_bg_skins", ["default"])
        if key not in user["owned_bg_skins"]:
            user["owned_bg_skins"].append(key)
        user["bg_skin"] = key
    elif item_type == "title":
        user.setdefault("owned_titles", ["none", "newbie"])
        if key not in user["owned_titles"]:
            user["owned_titles"].append(key)
        user["title"] = key


def add_coin_log(user, delta, reason):
    """记录一条金币变动明细（不负责落盘，由调用方在改动后 save_data）。
    delta 为变动量（+为收入，-为支出），reason 为来源说明。"""
    if not isinstance(user, dict):
        return
    log = user.get("coin_log")
    if not isinstance(log, list):
        log = []
        user["coin_log"] = log
    log.append({
        "t": int(time.time()),
        "delta": int(delta),
        "reason": reason,
        "balance": int(user.get("coins", 0)),
    })
    # 限制长度，避免无限增长
    if len(log) > 300:
        user["coin_log"] = log[-300:]


# 铭文被动结算加成系数（每级）：金币由 gold/luck 提供，分数由 wisdom/luck 提供。
# 2026-07-25 恢复：去掉原“封顶上限”，按等级线性缩放（Lv.N ≈ 系数×N）。
INS_COIN_MULT = {"gold": 1.0, "luck": 0.25}     # 本局金币 ×(1 + Σ系数×等级)
INS_SCORE_MULT = {"wisdom": 0.5, "luck": 0.25}  # 本局分数 ×(1 + Σ系数×等级)
def compute_inscription_bonus(user, equipped):
    """根据已装备铭文计算金币/分数加成倍率（coin_mult/score_mult）。
    仅统计服务端确认拥有的铭文，等级用服务端记录值（防客户端伪造等级刷分）。
    返回 (coin_mult, score_mult)，最终结算 = 基础值 ×(1 + mult)。"""
    owned = {}
    for ins in (user.get("inscriptions") or []):
        if isinstance(ins, dict) and ins.get("id"):
            owned[ins["id"]] = max(1, int(ins.get("level", 1)))
    coin_mult = 0.0
    score_mult = 0.0
    for eq in (equipped or []):
        if not isinstance(eq, dict):
            continue
        iid = eq.get("id")
        lvl = owned.get(iid)
        if not lvl:
            continue  # 未拥有则忽略（防作弊）
        if iid in INS_COIN_MULT:
            coin_mult += INS_COIN_MULT[iid] * lvl
        if iid in INS_SCORE_MULT:
            score_mult += INS_SCORE_MULT[iid] * lvl
    return coin_mult, score_mult


# ---- PROXY protocol (v1 文本 / v2 二进制) 解析 ----
# 背景：玩家通过 OpenFRP/frpc 公网穿透访问，frpc 在本机把请求转发给 127.0.0.1:8080，
#       导致 game_server.py 的 self.client_address[0] 永远是 127.0.0.1，看不到真实 IP。
# 解决：在 frpc/OpenFRP 控制台隧道配置里加 `proxy_protocol_version = "v2"`，
#       frpc 会在每个 TCP 连接前先发一段 PROXY 协议头（含真实客户端 IP+端口）。
#       本服务在 setup() 里 MSG_PEEK 探测并消费这段头，提取真实 IP。
# 安全：仅当 TCP 对端是 loopback/私网（即来自本机受信代理如 frpc）时才信任 PROXY 头，
#       防止远程客户端伪造 PROXY 头来刷 IP/绕过 IP 封禁。
PROXY_V1_PREFIX = b"PROXY "
PROXY_V2_SIG = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"  # 12 字节二进制签名


def _parse_proxy_protocol(data):
    """从 data 起始位置尝试解析 PROXY 协议 v1/v2。
    返回 (src_ip, src_port, header_len)；非 PROXY 协议返回 (None, None, 0)。"""
    # v1 文本："PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n"
    if data.startswith(PROXY_V1_PREFIX):
        idx = data.find(b"\r\n")
        if idx == -1 or idx > 512:
            return None, None, 0
        try:
            line = data[:idx].decode("ascii")
        except UnicodeDecodeError:
            return None, None, 0
        parts = line.split()
        if len(parts) >= 6 and parts[0] == "PROXY" and parts[1] in ("TCP4", "TCP6"):
            try:
                return parts[2], int(parts[4]), idx + 2
            except (ValueError, IndexError):
                pass
        return None, None, 0
    # v2 二进制：12 字节签名 + 版本/命令 + AF/PROTO + 地址长度 + 地址
    if data.startswith(PROXY_V2_SIG) and len(data) >= 16:
        ver_cmd = data[12]
        af_proto = data[13]
        addr_len = (data[14] << 8) | data[15]
        if ver_cmd != 0x21:  # 必须是 PROXY 命令（0x21），不是 LOCAL（0x20）
            return None, None, 0
        total = 16 + addr_len
        if len(data) < total:
            return None, None, 0
        if af_proto == 0x11:  # AF_INET (IPv4) + STREAM
            src_ip = ".".join(str(b) for b in data[16:20])
            src_port = (data[24] << 8) | data[25]
            return src_ip, src_port, total
        if af_proto == 0x21:  # AF_INET6 (IPv6) + STREAM
            parts = [f"{(data[16 + i * 2] << 8) | data[17 + i * 2]:x}" for i in range(8)]
            return ":".join(parts), (data[40] << 8) | data[41], total
        return None, None, 0
    return None, None, 0


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(http.server.SimpleHTTPRequestHandler):
    # 启用 HTTP/1.1：支持 keep-alive 与视频/大文件顺序流式播放（避免 HTTP/1.0 下视频必须整段下完才能播）
    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        self._proxy_ip = None
        self._proxy_port = None
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def setup(self):
        # 探测并消费 PROXY 协议头（仅当对端是 loopback/私网时信任，防伪造）
        sock = self.request
        try:
            sock.settimeout(3)
            peek = sock.recv(512, socket.MSG_PEEK)
            if peek:
                ip, port, hdr_len = _parse_proxy_protocol(peek)
                if hdr_len > 0 and self.client_address[0].startswith(LOCAL_IP_PREFIXES):
                    sock.recv(hdr_len)  # 真消费掉，避免 HTTP 解析器看到
                    self._proxy_ip = ip
                    self._proxy_port = port
                    # 覆写 client_address，让日志与所有下游逻辑都看到真实 IP
                    self.client_address = (ip, port or self.client_address[1])
        except Exception:
            pass
        finally:
            try:
                sock.settimeout(None)
            except Exception:
                pass
        super().setup()

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        path = (getattr(self, "path", "") or "").split("?")[0].lower()
        if path.startswith("/api/") or path.startswith("/admin"):
            # 动态接口不缓存，保证数据实时
            cache = "no-cache, no-store, must-revalidate"
        elif path in ("/", "") or path.endswith(".html") or path.endswith(".htm") or path.endswith(".json"):
            # 页面入口与数据不缓存，保证前端改动能即时生效（否则玩家要硬刷新才看得到）
            cache = "no-cache, no-store, must-revalidate"
        else:
            # 图片/视频/字体等真正静态资源长期缓存，避免抽奖等大资源反复下载导致卡顿
            cache = "public, max-age=86400"
        self.send_header("Cache-Control", cache)
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def require_auth(self, data):
        """Verify password. Returns (user, resolved_name) or (None, error_message)."""
        name = data.get("name", "")
        uid = data.get("uid", "")
        password = data.get("password", "")
        try:
            if name:
                name = sanitize_input(name, is_username=True)
            password = sanitize_password(password)
        except ValueError:
            return None, "输入包含非法内容"
        if not password:
            return None, "缺少密码"
        client_ip = self.get_client_ip()
        # 封禁校验：机器(uid) / IP
        banned, btype, reason, expires = is_banned(uid=uid, ip=client_ip)
        if banned:
            return None, format_ban(btype, reason, expires)
        user, resolved_name = resolve_user(name, uid)
        if user is None:
            return None, "用户不存在"
        # 账号封禁
        banned, btype, reason, expires = is_banned(name=resolved_name, uid=uid, ip=client_ip)
        if banned:
            return None, format_ban(btype, reason, expires)
        if not _verify_password(user.get("password"), password):
            return None, "密码错误"
        return user, resolved_name

    def _acquire_conn(self):
        """按真实客户端 IP 占用一个并发名额；超限直接 429 拒绝并返回 False。
        必须在请求处理入口调用，且配对调用 _release_conn()（建议 finally）。"""
        ip = self.get_client_ip()
        with _conn_lock:
            n = _conn_per_ip.get(ip, 0)
            if n >= MAX_CONCURRENT_PER_IP:
                try:
                    self.send_json({"error": "请求过于频繁，请稍后再试", "retry_after": 1}, 429)
                except Exception:
                    pass
                return False
            _conn_per_ip[ip] = n + 1
        return True

    def _release_conn(self):
        """释放当前请求的并发名额。"""
        ip = self.get_client_ip()
        with _conn_lock:
            n = _conn_per_ip.get(ip, 0)
            if n > 1:
                _conn_per_ip[ip] = n - 1
            else:
                _conn_per_ip.pop(ip, None)

    def do_GET(self):
        if not self._acquire_conn():
            return
        parsed = urlparse(self.path)
        is_admin_port = (self.server.server_address[1] == ADMIN_PORT)
        try:
            path = parsed.path
            is_admin_path = path.startswith("/api/admin") or path == "/admin.html" or path.startswith("/admin")
            if is_admin_port:
                # 8090 仅服务本机管理后台，拒绝一切非 admin 请求
                if not is_admin_path:
                    self.send_error(404)
                    return
                if path.startswith("/api/admin"):
                    self.handle_admin_get(parsed)
                else:
                    # /admin.html 及 /admin* 静态页面（本机端口，直接放行）
                    super().do_GET()
                return
            # 8080 游戏端口：默认公网不暴露管理后台；云端设 ADMIN_REMOTE 后放行
            if is_admin_path and not os.environ.get("ADMIN_REMOTE"):
                self.send_error(404)
                return
            if is_admin_path:
                if path.startswith("/api/admin"):
                    self.handle_admin_get(parsed)
                else:
                    super().do_GET()
                return
            if path.startswith("/api/race"):
                race_server.handle_race_get(self, parsed)
            elif path.startswith("/api/"):
                self.handle_api_get(parsed)
            else:
                self.serve_static_with_range()
        except Exception as e:
            try:
                self.send_json({"error": "服务器内部错误"}, 500)
            except Exception:
                pass
            print("[do_GET error]", repr(e))
        finally:
            self._release_conn()

    def _send_static_error(self, code, msg):
        """安全地返回静态错误响应。
        注意：本环境 HTTP/1.1 下标准库 send_error() 会抛异常导致连接挂起，故自行按 send_json 的模式发送。"""
        try:
            body = msg.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def serve_static_with_range(self):
        """支持 Range 的静态文件服务：视频/大文件可断点续传与分片缓冲。
        仅服务 DIRECTORY(rolling-ball) 内的资源，禁止目录穿越（防 game_data.json 等泄露）。
        兼容 /rolling-ball/xxx 与 /xxx 两种访问方式；任何异常都返回 404 而非 500。"""
        import re
        try:
            rel = self.path.split("?")[0]
            if rel.startswith("/rolling-ball"):
                # 兼容 /rolling-ball/xxx 与 /xxx 两种访问方式
                rel = rel[len("/rolling-ball"):] or "/"
            rel = rel.lstrip("/")
            base = os.path.normpath(DIRECTORY)
            path = os.path.normpath(os.path.join(base, rel))
            # 防目录穿越：只允许访问 DIRECTORY 内部
            if path != base and not path.startswith(base + os.sep):
                self._send_static_error(403, "禁止访问")
                return
            if os.path.isdir(path):
                idx = os.path.join(path, "index.html")
                if os.path.isfile(idx):
                    path = idx
                else:
                    self._send_static_error(404, "文件不存在")
                    return
            if not os.path.isfile(path):
                self._send_static_error(404, "文件不存在")
                return
            ctype = self.guess_type(path)
            try:
                size = os.path.getsize(path)
            except OSError:
                self._send_static_error(404, "文件不存在")
                return
            rng = self.headers.get("Range")
            if rng:
                m = re.match(r"bytes=(\d*)-(\d*)", rng.strip())
                if m:
                    start_s, end_s = m.group(1), m.group(2)
                    start = int(start_s) if start_s else 0
                    end = int(end_s) if end_s else size - 1
                    if start > end or start >= size or end >= size:
                        self.send_response(416)
                        self.send_header("Content-Range", "bytes */%d" % size)
                        self.end_headers()
                        return
                    self.send_response(206)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
                    self.send_header("Content-Length", str(end - start + 1))
                    self.end_headers()
                    self._send_range_body(path, start, end)
                    return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            try:
                with open(path, "rb") as f:
                    shutil.copyfileobj(f, self.wfile)
            except (BrokenPipeError, ConnectionResetError):
                pass
        except Exception as e:
            self._send_static_error(404, "文件不存在")
            print("[static error]", repr(e))

    def _send_range_body(self, path, start, end):
        remaining = end - start + 1
        try:
            with open(path, "rb") as f:
                f.seek(start)
                buf = 64 * 1024
                while remaining > 0:
                    data = f.read(min(buf, remaining))
                    if not data:
                        break
                    self.wfile.write(data)
                    remaining -= len(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        if not self._acquire_conn():
            return
        parsed = urlparse(self.path)
        is_admin_port = (self.server.server_address[1] == ADMIN_PORT)
        try:
            path = parsed.path
            if is_admin_port:
                # 8090 仅服务本机管理后台写接口
                if not path.startswith("/api/admin"):
                    self.send_error(404)
                    return
                self.handle_admin_post(parsed)
                return
            # 8080 游戏端口：默认拒绝 admin 写接口；云端设 ADMIN_REMOTE 后放行
            if path.startswith("/api/admin") and not os.environ.get("ADMIN_REMOTE"):
                self.send_error(404)
                return
            if path.startswith("/api/admin"):
                self.handle_admin_post(parsed)
                return
            if path.startswith("/api/race"):
                race_server.handle_race(self, parsed)
            elif path.startswith("/api/"):
                self.handle_api_post(parsed)
            else:
                self.send_error(404)
        except Exception as e:
            try:
                self.send_json({"error": "服务器内部错误"}, 500)
            except Exception:
                pass
            print("[do_POST error]", repr(e))
        finally:
            self._release_conn()

    # ---- API GET ----
    def handle_api_get(self, parsed):
        path = parsed.path
        qs = parse_qs(parsed.query)
        client_ip = self.get_client_ip()

        # Rate limit reads
        allowed, retry = check_rate_limit(client_ip, is_post=False)
        if not allowed:
            self.send_json({"error": "请求过于频繁", "retry_after": retry}, 429)
            return

        # IP 封禁：拦截该网络读取游戏数据（公告与验证码除外，确保登录界面仍可显示封禁提示）
        if path != "/api/announcement" and path != "/api/captcha":
            banned, btype, reason, expires = is_banned(ip=client_ip)
            if banned:
                self.send_json({"error": format_ban(btype, reason, expires), "banned": True, "ban_type": btype, "expires": expires}, 403)
                return

        if path == "/api/announcement":
            ann = game_data.get("announcement", {})
            self.send_json({
                "title": ann.get("title", "欢迎来到滚动的小球"),
                "text": ann.get("text", "如有疑问请联系服主！"),
                "contact": ann.get("contact", ""),
                "enabled": ann.get("enabled", True),
            })
            return

        if path == "/api/user":
            # 敏感信息：必须认证，只能查自己
            name = qs.get("name", [""])[0]
            uid = qs.get("uid", [""])[0]
            password = qs.get("password", [""])[0]
            try:
                if name:
                    name = sanitize_input(name, is_username=True)
                password = sanitize_password(password)
            except ValueError:
                self.send_json({"error": "输入包含非法内容"})
                return
            if not password:
                self.send_json({"error": "缺少密码"}, 401)
                return
            user, resolved_name = resolve_user(name, uid)
            if user is None:
                self.send_json({"error": "用户不存在"}, 401)
                return
            if not _verify_password(user.get("password"), password):
                self.send_json({"error": "密码错误"}, 401)
                return
            self.send_json(get_user_safe(user, resolved_name or name))

        elif path == "/api/captcha":
            captcha_id, svg = generate_captcha_svg()
            self.send_json({"captcha_id": captcha_id, "svg": svg})

        elif path == "/api/leaderboard":
            self.send_json(game_data["leaderboards"])

        elif path == "/api/chat/get":
            since = int(qs.get("since", ["0"])[0])
            msgs = [m for m in chat_messages if m["timestamp"] > since]
            self.send_json({"messages": msgs})

        else:
            self.send_error(404)

    # ---- API POST ----
    def handle_api_post(self, parsed):
        client_ip = self.get_client_ip()
        # 串行化所有写请求，消除并发双花/双抽/数据竞争
        with WRITE_LOCK:
            self._handle_api_post_locked(parsed, client_ip)

    def _handle_api_post_locked(self, parsed, client_ip):
        path = parsed.path

        # 先读取请求体（仅一次），用于按账号维度限流
        cl = int(self.headers.get("Content-Length", 0))
        try:
            raw = self.rfile.read(cl).decode("utf-8") if cl > 0 else "{}"
        except UnicodeDecodeError:
            self.send_json({"error": "请求编码无效"}, 400)
            return
        try:
            data = json.loads(raw)
        except Exception:
            data = {}

        # Rate limit writes（已登录请求按账号维度限流，避免隧道下全员共用 127.0.0.1 桶被一人拖垮）
        subkey = (data.get("uid") or data.get("name") or "") if isinstance(data, dict) else ""
        allowed, retry = check_rate_limit(client_ip, is_post=True, subkey=subkey)
        if not allowed:
            self.send_json({"error": "请求过于频繁", "retry_after": retry}, 429)
            return

        # IP 封禁：拦截该网络的所有游戏接口请求
        banned, btype, reason, expires = is_banned(ip=client_ip)
        if banned:
            self.send_json({"error": format_ban(btype, reason, expires), "banned": True, "ban_type": btype, "expires": expires}, 403)
            return

        if path == "/api/login":
            name = data.get("name", "")
            uid = data.get("uid", "")
            password = data.get("password", "")
            try:
                if name:
                    name = sanitize_input(name, is_username=True)
                password = sanitize_password(password)
            except ValueError:
                self.send_json({"error": "输入包含非法内容"})
                return
            if not password:
                self.send_json({"error": "密码不能为空"})
                return
            # Check login lockout BEFORE auth to prevent brute-force（按账号维度，防全局锁）
            locked, retry_after = check_login_lockout(client_ip, name)
            if locked:
                self.send_json({"error": "登录尝试过多，请稍后再试", "retry_after": retry_after}, 429)
                return
            # 封禁校验：账号名 / 机器(uid) / IP（用户不存在也拦截，防止用被封昵称重试）
            banned, btype, reason, expires = is_banned(name=name, uid=uid, ip=client_ip)
            if banned:
                self.send_json({"error": format_ban(btype, reason, expires), "banned": True, "ban_type": btype, "expires": expires}, 403)
                return
            # Resolve by uid (stable) first, then by name
            user, resolved_name = resolve_user(name, uid)
            if user is None:
                if data.get("auto"):
                    # 自动登录（cookie 过期/改名后残留旧名）: 绝不创建 phantom 账户，
                    # 直接提示重新登录，由前端清理过期 cookie。
                    self.send_json({"error": "登录已失效，请重新登录", "expired": True})
                    return
                if not name:
                    self.send_json({"error": "用户名不能为空"})
                    return
                # 不再自动注册，引导到注册接口并填写验证码
                self.send_json({"error": "用户不存在，请先注册", "need_register": True}, 401)
                return
            # Existing user — verify password
            stored_pwd = user.get("password")
            if stored_pwd is None:
                # 无密码遗留账号：必须凭注册邮箱或原始注册 IP 认领，否则任意人可冒名登录
                email = user.get("email")
                reg_ip = user.get("reg_ip")
                cur_ip = self.get_client_ip()
                if email:
                    if data.get("email", "") != email:
                        self.send_json({"error": "该无密码账号需验证注册邮箱才能认领，邮箱不正确", "need_email": True})
                        return
                elif reg_ip and reg_ip not in ("127.0.0.1", "::1") and reg_ip != cur_ip:
                    self.send_json({"error": "该无密码账号需从注册 IP 登录才能认领，当前网络不符", "need_ip": True})
                    return
                else:
                    # 既无邮箱也无可用注册 IP：无法安全认领，拒绝直接登录，需联系服主后台重置
                    self.send_json({"error": "该账号为无密码遗留账号，存在冒名风险，请先在后台绑定邮箱或联系服主重置密码"})
                    return
                if not _strong_password(password):
                    self.send_json({"error": "密码强度不足：至少 %d 位且不能为常见弱密码" % MIN_PASSWORD_LEN})
                    return
                user["password"] = _hash_password(password)
                user["last_ip"] = client_ip
                user["last_online"] = int(time.time())
                save_data(game_data)
                safe = get_user_safe(user, resolved_name)
                self.send_json({"ok": True, "action": "migrate", "user": safe})
            elif not _verify_password(stored_pwd, password):
                record_login_failure(client_ip, name)
                self.send_json({"error": "密码错误"})
                return
            else:
                user["last_ip"] = client_ip
                user["last_online"] = int(time.time())
                # 旧明文账号首次成功登录后升级为哈希（幂等：已是哈希则跳过）
                if not _is_pwd_hashed(stored_pwd):
                    user["password"] = _hash_password(password)
                save_data(game_data)
                safe = get_user_safe(user, resolved_name)
                self.send_json({"ok": True, "action": "login", "user": safe})

        elif path == "/api/register":
            name = data.get("name", "")
            password = data.get("password", "")
            captcha_id = data.get("captcha_id", "")
            captcha_answer = data.get("captcha_answer", "")
            try:
                name = sanitize_input(name, is_username=True)
                password = sanitize_password(password)
            except ValueError:
                self.send_json({"error": "输入包含非法内容"})
                return
            if not name or not password:
                self.send_json({"error": "用户名和密码不能为空"})
                return
            if not _strong_password(password):
                self.send_json({"error": "密码强度不足：至少 %d 位且不能为常见弱密码" % MIN_PASSWORD_LEN})
                return
            if name.lower() in RESERVED_ADMIN_NAMES:
                self.send_json({"error": "该用户名受保护，不可注册"})
                return
            if name in game_data["users"]:
                self.send_json({"error": "用户名已被占用"})
                return
            # 注册同样受封禁限制（账号名 / 机器uid / IP）
            banned, btype, reason, expires = is_banned(name=name, uid=data.get("uid", ""), ip=client_ip)
            if banned:
                self.send_json({"error": format_ban(btype, reason, expires), "banned": True, "ban_type": btype, "expires": expires}, 403)
                return
            # Check registration rate limits
            ok, reason = check_registration_limit(client_ip)
            if not ok:
                self.send_json({"error": reason}, 429)
                return
            # Verify captcha
            if not verify_captcha(captcha_id, captcha_answer):
                self.send_json({"error": "验证码错误或已过期", "captcha_invalid": True})
                return
            # Create user
            user = {
                "uid": gen_uid(),
                "password": _hash_password(password),
                "email": "",
                "coins": 0,
                "owned_ball_skins": ["default"],
                "owned_bg_skins": ["default"],
                "ball_skin": "default",
                "bg_skin": "default",
                "save": None,
                "title": "newbie",
                "owned_titles": ["none", "newbie"],
                "chat_color": "#e2e8f0",
                "inscriptions": [],
                "equipped": [],
                "reg_ip": client_ip,
                "last_ip": client_ip,
                "last_online": int(time.time()),
            }
            game_data["users"][name] = user
            record_registration(client_ip)
            save_data(game_data)
            safe = get_user_safe(user, name)
            self.send_json({"ok": True, "action": "register", "user": safe})

        elif path == "/api/user":
            # 安全：只允许已登录用户修改自己的非敏感资料
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            # 只允许修改这些字段；金币、皮肤、称号、max_level 等禁止直写
            # save 仅作为客户端存档备份，排行榜/金币以服务端权威接口为准
            allowed = {"email", "ball_skin", "bg_skin", "chat_color", "save"}
            for key in allowed:
                if key not in data:
                    continue
                if key == "chat_color":
                    user[key] = sanitize_chat_color(data[key])
                elif key == "save":
                    s = data[key]
                    if isinstance(s, dict):
                        try:
                            raw = json.dumps(s, ensure_ascii=False)
                        except Exception:
                            raw = ""
                        if len(raw) > 20000:
                            self.send_json({"error": "存档过大（上限 20KB）"})
                            return
                        user["save"] = s
                elif key == "email":
                    em = data[key]
                    if em and not EMAIL_RE.match(em):
                        self.send_json({"error": "邮箱格式不正确"})
                        return
                    user["email"] = em
                elif key in ("ball_skin", "bg_skin"):
                    # 安全：只允许装备自己已拥有的皮肤，禁止直写未购买的皮肤
                    # （含 owner 专属皮肤冒名），越权值直接忽略。
                    val = data[key]
                    owned_key = "owned_ball_skins" if key == "ball_skin" else "owned_bg_skins"
                    owned = user.get(owned_key)
                    if isinstance(owned, list) and val in owned:
                        user[key] = val
                else:
                    user[key] = data[key]
            if resolved_name:
                game_data["users"][resolved_name] = user
            save_data(game_data)
            self.send_json({"ok": True, "user": get_user_safe(user, resolved_name or data.get("name", ""))})

        elif path == "/api/level/up":
            # 客户端每过一关上报：服务端权威记账，逐级递增；跳关/刷频次直接拒绝
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": user is None and resolved_name or "鉴权失败"}, 401)
                return
            uid = user.get("uid")
            level = data.get("level", 0)
            try:
                level = int(level)
            except (TypeError, ValueError):
                self.send_json({"error": "关卡值非法"})
                return
            if level < 1 or level > 100000:
                self.send_json({"error": "关卡超出范围"})
                return
            # 速率限制：同一账号两次成功上报至少间隔 N 秒，防止脚本连刷
            now = time.time()
            last = last_level_up.get(uid, 0)
            if now - last < LEVEL_UP_COOLDOWN:
                self.send_json({"ok": False, "rejected": True, "reason": f"上报太频繁，请等待 {LEVEL_UP_COOLDOWN} 秒"})
                return
            cur = user.get("max_level", 1)
            # 防作弊核心：只能比历史最高多 1 关（逐级递增），跳传大数拒绝；重玩低关不降
            if level > cur + 1:
                self.send_json({"ok": False, "rejected": True, "max_level": cur,
                                "reason": "禁止跳关"})
                return
            if level > cur:
                user["max_level"] = level
                last_level_up[uid] = now
                if resolved_name:
                    game_data["users"][resolved_name] = user
                save_data(game_data)
            self.send_json({"ok": True, "max_level": user.get("max_level", 1)})

        elif path == "/api/leaderboard":
            # 安全：必须认证；服务端按「本局获得」累加，不信任客户端累计总额，杜绝上报虚高总额刷币
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            name = resolved_name or data.get("name", "")
            uid = user.get("uid")
            max_lv = user.get("max_level", 1)
            # 铭文被动结算加成：按本局装备的 黄金/智慧/幸运 铭文（含等级）计算金币/分数倍率
            equipped = data.get("equipped")
            coin_mult, score_mult = compute_inscription_bonus(user, equipped)
            # 经济上限：单局/窗口增量封顶 = min(max_lv, HARD_CAP_LEVEL) × 每关上限。
            # max_level 可被 /api/level/up 无凭证泵高，故用 HARD_CAP_LEVEL 封顶，掐断经济上限被无限放大。
            eff_lv = min(max(max_lv, 1), HARD_CAP_LEVEL)
            cap = eff_lv * GAME_COIN_CAP_PER_LEVEL
            score_cap = eff_lv * 10000
            now = time.time()
            # 本局获得：优先 earned_coins/earned_score（前端改报「本局获得」）。
            # 旧前端可能仍传累计总额 coins/score，降级按 delta 处理（同样受 cap/窗口限制）。
            if "earned_coins" in data or "earned_score" in data:
                try:
                    earned = max(0, int(data.get("earned_coins", 0)))
                except (TypeError, ValueError):
                    earned = 0
                try:
                    game_score = max(0, int(data.get("earned_score", 0)))
                except (TypeError, ValueError):
                    game_score = 0
            else:
                try:
                    client_coins = max(0, int(data.get("coins", 0)))
                except (TypeError, ValueError):
                    client_coins = 0
                server_coins = max(0, int(user.get("coins", 0)))
                earned = max(0, client_coins - server_coins)   # 仅接受增加量（降级兼容）
                try:
                    game_score = max(0, int(data.get("score", 0)))
                except (TypeError, ValueError):
                    game_score = 0
            # 金币：钳到单局上限 + 铭文加成；原 SETTLE_COOLDOWN early-return 已移除——改为始终累加，
            # 由 _accrual_cap 窗口上限兜底防重放，避免玩家两局死亡间隔<2s 时第二局金币被静默丢弃。
            earned = round(min(earned, cap) * (1 + coin_mult))
            earned = _accrual_cap(uid, "coins", earned, GAME_ACCRUAL_WINDOW, cap)
            server_coins = max(0, int(user.get("coins", 0)))
            user["coins"] = server_coins + earned
            if earned > 0:
                add_coin_log(user, earned, "游戏结算·关卡%d（含铭文加成）" % max_lv)
            # score：钳到单局上限 + 铭文加成
            game_score = round(min(game_score, score_cap) * (1 + score_mult))
            game_score = _accrual_cap(uid, "score", game_score, GAME_ACCRUAL_WINDOW, score_cap)
            if not isinstance(user.get("total_score"), int):
                # 首次迁移：用已有榜单分数作为起点，避免历史成绩丢失
                existing = 0
                for e in game_data["leaderboards"].get("score", []):
                    if e.get("name") == name:
                        existing = int(e.get("value", 0)); break
                user["total_score"] = existing
            user["total_score"] = int(user.get("total_score", 0)) + game_score
            for key, val in [("coins", user["coins"]), ("score", user["total_score"])]:
                board = game_data["leaderboards"][key]
                board = [e for e in board if e["name"] != name]
                board.append({"name": name, "value": val})
                board.sort(key=lambda x: x["value"], reverse=True)
                game_data["leaderboards"][key] = board[:50]
            lvl_board = game_data["leaderboards"]["level"]
            lvl_board = [e for e in lvl_board if e["name"] != name]
            lvl_board.append({"name": name, "value": max_lv})
            lvl_board.sort(key=lambda x: x["value"], reverse=True)
            game_data["leaderboards"]["level"] = lvl_board[:50]
            last_settle[uid] = now
            user["last_online"] = int(now)
            save_data(game_data)
            self.send_json({"ok": True, "coins": user["coins"], "score": user["total_score"], "max_level": max_lv})

        elif path == "/api/shop/buy":
            # 安全购买：服务端校验价格、扣金币、发放物品并装备；禁止客户端直写 coins/owned
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            item_type = data.get("type", "")
            key = data.get("key", "")
            if item_type not in SHOP_ITEMS or key not in SHOP_ITEMS[item_type]:
                self.send_json({"error": "商品不存在"})
                return
            price = SHOP_ITEMS[item_type][key]
            # owner 称号只允许服主购买/拥有
            if key == "owner":
                is_owner = (resolved_name == OWNER_NAME) or (OWNER_UID and user.get("uid") == OWNER_UID)
                if not is_owner:
                    self.send_json({"error": "该称号无法购买"})
                    return
            if is_owned_key(user, item_type, key):
                # 已拥有：直接装备
                grant_item(user, item_type, key)
            elif price < 0:
                self.send_json({"error": "该商品无法购买"})
                return
            else:
                coins = max(0, int(user.get("coins", 0)))
                if coins < price:
                    self.send_json({"error": "金币不足"})
                    return
                user["coins"] = coins - price
                add_coin_log(user, -price, "商城购买·" + key)
                grant_item(user, item_type, key)
            if resolved_name:
                game_data["users"][resolved_name] = user
            save_data(game_data)
            self.send_json({"ok": True, "user": get_user_safe(user, resolved_name or data.get("name", ""))})

        elif path == "/api/lottery/draw":
            # 抽奖：扣 100 金币，按权重抽取并发放（铭文入库 / 返金币 / 谢谢参与）
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            coins = max(0, int(user.get("coins", 0)))
            ins = user.setdefault("inscriptions", [])
            # 幸运铭文已改为可装备的局内铭文（不再用于免费抽），此处按固定价扣费
            if coins < LOTTERY_COST:
                self.send_json({"error": "金币不足，每次抽奖需要 %d 金币（当前 %d）" % (LOTTERY_COST, coins)})
                return
            user["coins"] = coins - LOTTERY_COST
            add_coin_log(user, -LOTTERY_COST, "抽奖(单抽)")
            # 按权重抽取（应用该用户 drop_rate 倍率）
            chosen = _lottery_roll(user)
            result = {"id": chosen["id"], "name": chosen["name"],
                      "type": chosen["type"], "rarity": chosen["rarity"]}
            if chosen["type"] == "inscription":
                ins = user.setdefault("inscriptions", [])
                ins.append({"id": chosen["id"], "level": 1})
            elif chosen["type"] == "coins":
                amt = int(chosen.get("amount", 0))
                user["coins"] = int(user["coins"]) + amt
                add_coin_log(user, amt, "抽奖奖励·金币+%d" % amt)
                result["amount"] = amt
            if resolved_name:
                game_data["users"][resolved_name] = user
            save_data(game_data)
            self.send_json({"ok": True, "item": result, "coins": user["coins"],
                            "inscriptions": user.get("inscriptions", [])})

        elif path == "/api/lottery/draw10":
            # 十连抽：消耗 1000 金币（幸运铭文每张抵 1 次，最多 10 次免费），
            # 按权重抽 10 次发放，返回 results 数组。
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            coins = max(0, int(user.get("coins", 0)))
            ins = user.setdefault("inscriptions", [])
            # 幸运铭文已改为可装备的局内铭文，不再抵扣抽卡；十连固定 1000 金币
            paid = 10 * LOTTERY_COST
            if coins < paid:
                self.send_json({"error": "金币不足，十连抽需要 %d 金币（当前 %d）" % (paid, coins)})
                return
            user["coins"] = coins - paid
            add_coin_log(user, -paid, "抽奖(十连)")
            results = []
            for _ in range(10):
                # 按权重抽取（应用该用户 drop_rate 倍率）
                chosen = _lottery_roll(user)
                result = {"id": chosen["id"], "name": chosen["name"],
                          "type": chosen["type"], "rarity": chosen["rarity"]}
                if chosen["type"] == "inscription":
                    ins.append({"id": chosen["id"], "level": 1})
                elif chosen["type"] == "coins":
                    amt = int(chosen.get("amount", 0))
                    user["coins"] = int(user["coins"]) + amt
                    add_coin_log(user, amt, "抽奖奖励·金币+%d" % amt)
                    result["amount"] = amt
                results.append(result)
            if resolved_name:
                game_data["users"][resolved_name] = user
            save_data(game_data)
            self.send_json({"ok": True, "results": results, "coins": user["coins"],
                            "inscriptions": user.get("inscriptions", [])})

        elif path == "/api/inscription/equip":
            # 保存本局装备（最多 2 个）；仅允许选择自己拥有的铭文（按 id+level 校验）
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            items = data.get("items") or []
            if not isinstance(items, list):
                items = []
            owned = user.get("inscriptions", [])
            _own_ct = {}
            for _it in owned:
                if isinstance(_it, dict) and _it.get("id"):
                    _k = (_it["id"], int(_it.get("level", 1)))
                    _own_ct[_k] = _own_ct.get(_k, 0) + 1
            chosen = []
            for _e in items[:2]:
                if not isinstance(_e, dict):
                    continue
                _ek = (_e.get("id"), int(_e.get("level", 1)))
                if _own_ct.get(_ek, 0) > 0:
                    _own_ct[_ek] -= 1
                    chosen.append({"id": _e["id"], "level": int(_e.get("level", 1))})
            user["equipped"] = chosen
            if resolved_name:
                game_data["users"][resolved_name] = user
            save_data(game_data)
            self.send_json({"ok": True, "equipped": chosen, "inscriptions": user.get("inscriptions", [])})

        elif path == "/api/inscription/synthesize":
            # 合成：消耗 2 张同 id+level 铭文 → 1 张 level+1（等级不限上限）
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            sid = data.get("id", "")
            try:
                slv = int(data.get("level", 1))
            except (TypeError, ValueError):
                slv = 1
            ins = user.get("inscriptions", [])
            if not isinstance(ins, list):
                ins = []
            idxs = [i for i, it in enumerate(ins)
                    if isinstance(it, dict) and it.get("id") == sid and int(it.get("level", 1)) == slv]
            if len(idxs) < 2:
                self.send_json({"error": "该等级铭文不足 2 个，无法合成"}, 400)
                return
            new_ins = [it for i, it in enumerate(ins) if i not in (idxs[0], idxs[1])]
            new_ins.append({"id": sid, "level": slv + 1})
            user["inscriptions"] = new_ins
            # 清理装备中因合成而不再存在的铭文引用
            eq = user.get("equipped", [])
            if isinstance(eq, list):
                _own_ct = {}
                for _it in new_ins:
                    if isinstance(_it, dict) and _it.get("id"):
                        _k = (_it["id"], int(_it.get("level", 1)))
                        _own_ct[_k] = _own_ct.get(_k, 0) + 1
                user["equipped"] = [e for e in eq
                                    if isinstance(e, dict)
                                    and _own_ct.get((e.get("id"), int(e.get("level", 1))), 0) > 0]
            if resolved_name:
                game_data["users"][resolved_name] = user
            save_data(game_data)
            self.send_json({"ok": True, "inscriptions": new_ins, "equipped": user.get("equipped", [])})

        elif path == "/api/bind_email":
            name = data.get("name", "")
            password = data.get("password", "")
            email = data.get("email", "")
            try:
                name = sanitize_input(name, is_username=True)
                password = sanitize_password(password)
                email = sanitize_input(email)
            except ValueError:
                self.send_json({"error": "输入包含非法内容"})
                return
            if not name or not password:
                self.send_json({"error": "用户名和密码不能为空"})
                return
            user = game_data["users"].get(name)
            if not user:
                self.send_json({"error": "用户不存在"})
                return
            if not _verify_password(user.get("password"), password):
                self.send_json({"error": "密码错误"})
                return
            if email and not EMAIL_RE.match(email):
                self.send_json({"error": "邮箱格式不正确"})
                return
            user["email"] = email
            save_data(game_data)
            self.send_json({"ok": True, "email": email})

        elif path == "/api/change_password":
            name = data.get("name", "")
            uid = data.get("uid", "")
            password = data.get("password", "")
            new_password = data.get("new_password", "")
            try:
                name = sanitize_input(name, is_username=True)
                password = sanitize_password(password)
                new_password = sanitize_password(new_password)
            except ValueError:
                self.send_json({"error": "输入包含非法内容"})
                return
            if not name or not password:
                self.send_json({"error": "用户名和密码不能为空"})
                return
            if not new_password:
                self.send_json({"error": "新密码不能为空"})
                return
            if len(new_password) > 20:
                self.send_json({"error": "新密码长度需在 1-20 字之间"})
                return
            if not _strong_password(new_password):
                self.send_json({"error": "新密码强度不足：至少 %d 位且不能为常见弱密码" % MIN_PASSWORD_LEN})
                return
            if new_password == password:
                self.send_json({"error": "新密码不能与当前密码相同"})
                return
            client_ip = self.get_client_ip()
            banned, btype, reason, expires = is_banned(name=name, uid=uid, ip=client_ip)
            if banned:
                self.send_json({"error": format_ban(btype, reason, expires), "banned": True}, 403)
                return
            user, resolved_name = resolve_user(name, uid)
            if user is None:
                self.send_json({"error": "用户不存在"})
                return
            if not _verify_password(user.get("password"), password):
                self.send_json({"error": "当前密码错误"})
                return
            user["password"] = _hash_password(new_password)
            save_data(game_data)
            self.send_json({"ok": True, "message": "密码修改成功"})

        elif path == "/api/coin_log":
            user, resolved_name = self.require_auth(data)
            if user is None:
                self.send_json({"error": resolved_name}, 401)
                return
            log = user.get("coin_log")
            if not isinstance(log, list):
                # 首次访问：以当前余额播种一条历史基线，便于查看（含本功能上线前的累计余额）
                bal = int(user.get("coins", 0))
                log = [{"t": int(time.time()), "delta": bal, "reason": "历史余额", "balance": bal}]
                user["coin_log"] = log
                save_data(game_data)
            # 最新的在前返回
            self.send_json({"ok": True, "coin_log": list(reversed(log)), "coins": int(user.get("coins", 0))})

        elif path == "/api/chat/send":
            name = data.get("name", "")
            uid = data.get("uid", "")
            password = data.get("password", "")
            text = data.get("text", "")
            try:
                if name:
                    name = sanitize_input(name, is_username=True)
                text = sanitize_input(text)
            except ValueError:
                self.send_json({"error": "输入包含非法内容"})
                return
            if not text:
                self.send_json({"error": "消息不能为空"})
                return
            if len(text) > 100:
                self.send_json({"error": "消息过长（最多100字）"})
                return
            # Resolve by uid (stable) first, then by name
            user, resolved_name = resolve_user(name, uid)
            if not user or not resolved_name:
                self.send_json({"error": "用户不存在"})
                return
            if not _verify_password(user.get("password"), password):
                self.send_json({"error": "密码错误"})
                return
            # 封禁校验：账号名 / 机器(uid) / IP（与登录/结算一致，防止被封禁者仍能发言）
            banned, btype, reason, expires = is_banned(name=resolved_name, uid=uid, ip=client_ip)
            if banned:
                self.send_json({"error": format_ban(btype, reason, expires), "banned": True, "ban_type": btype, "expires": expires}, 403)
                return
            # 单用户聊天频率限制（防刷屏/脚本）
            allowed, retry = check_chat_rate(uid)
            if not allowed:
                self.send_json({"error": "发言过于频繁，请稍后再试", "retry_after": retry}, 429)
                return
            title_key = user.get("title", "newbie")
            chat_color = user.get("chat_color", "#e2e8f0")
            is_owner = (resolved_name == OWNER_NAME) or (OWNER_UID and user.get("uid") == OWNER_UID)
            if is_owner:
                title_key = OWNER_TITLE_KEY
                chat_color = OWNER_CHAT_COLOR
            msg = {
                "name": resolved_name,
                "text": text,
                "timestamp": int(time.time()),
                "title_key": title_key,
                "chat_color": chat_color,
            }
            chat_messages.append(msg)
            if len(chat_messages) > MAX_CHAT_MESSAGES:
                chat_messages.pop(0)
            self.send_json({"ok": True, "message": msg})

        else:
            self.send_error(404)

    # ---- Admin helpers ----
    def _peer_is_trusted_proxy(self):
        """TCP 对端是否来自本机/私网（即 frpc 这类受信代理）。
        仅在此前提下才信任 X-Forwarded-For / X-Real-IP，否则直连 8080 的
        客户端可伪造这些头绕过按 IP 的限速/封禁。"""
        if os.environ.get("TRUST_XFF"):
            return True
        return self.client_address[0].startswith(LOCAL_IP_PREFIXES)

    def get_client_ip(self):
        """Return real client IP. Priority: PROXY protocol (from loopback) > X-Forwarded-For > X-Real-IP > client_address.

        XFF/XRI 仅在 TCP 对端为受信代理（loopback/私网，如 frpc）时才信任，
        直连 8080 的外部客户端伪造这些头无效。"""
        # PROXY 协议（最高优先级，仅当来自 loopback 的可信代理时才设置，防伪造）
        if self._proxy_ip:
            return clean_ip(self._proxy_ip)
        if self._peer_is_trusted_proxy():
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                ip = xff.split(",")[0].strip()
                if ip:
                    return clean_ip(ip)
            xri = self.headers.get("X-Real-IP")
            if xri:
                ip = xri.split(",")[0].strip()
                if ip:
                    return clean_ip(ip)
        return clean_ip(self.client_address[0])

    def is_local(self):
        ip = self.client_address[0]
        return ip.startswith(LOCAL_IP_PREFIXES)

    def check_admin_auth(self):
        """Check IP restriction + admin credentials. Returns True if authorized.
        含暴力破解防护：失败过多按真实 IP 临时锁定。"""
        # 云端设 ADMIN_REMOTE 后放行远程后台（仍须 Basic Auth 密码），否则仅限本机
        if not self.is_local() and not os.environ.get("ADMIN_REMOTE"):
            self.send_json({"error": "禁止访问：仅限内网"}, status=403)
            return False
        client_ip = self.get_client_ip()
        # 暴力破解防护：失败次数过多先锁定一段时间
        locked, retry = check_admin_lockout(client_ip)
        if locked:
            self.send_json({"error": "管理员登录尝试过多，已临时锁定", "retry_after": retry}, 429)
            return False
        # Check Authorization header (Basic auth)
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            self.send_json({"error": "未认证"}, status=401)
            return False
        import base64
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            user, pwd = decoded.split(":", 1)
        except Exception:
            self.send_json({"error": "认证格式错误"}, status=401)
            return False
        if user != ADMIN_USER or pwd != ADMIN_PASS:
            record_admin_failure(client_ip)
            self.send_json({"error": "管理员账号或密码错误"}, status=401)
            return False
        # 成功后清空该 IP 失败计数
        admin_fail_store.pop(client_ip, None)
        return True

    def handle_admin_get(self, parsed):
        if not self.is_local() and not os.environ.get("ADMIN_REMOTE"):
            self.send_json({"error": "禁止访问：仅限内网"}, status=403)
            return
        # 后台独立限速，防扫描/爆破
        allowed, retry = check_admin_rate_limit(self.get_client_ip())
        if not allowed:
            self.send_json({"error": "请求过于频繁", "retry_after": retry}, 429)
            return
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/api/admin/check":
            # Just verify auth
            if self.check_admin_auth():
                self.send_json({"ok": True, "message": "管理员已认证"})
            return

        if not self.check_admin_auth():
            return

        if path == "/api/admin/users":
            # Return all users (without passwords)
            users_safe = {}
            for name, u in game_data["users"].items():
                users_safe[name] = {k: v for k, v in u.items() if k != "password"}
            self.send_json({"users": users_safe})

        elif path == "/api/admin/leaderboards":
            self.send_json({"leaderboards": game_data["leaderboards"]})

        elif path == "/api/admin/stats":
            total_users = len(game_data["users"])
            total_coins = sum(u.get("coins", 0) for u in game_data["users"].values())
            total_lb_entries = sum(len(b) for b in game_data["leaderboards"].values())
            emails_bound = sum(1 for u in game_data["users"].values() if u.get("email"))
            self.send_json({
                "total_users": total_users,
                "total_coins": total_coins,
                "total_leaderboard_entries": total_lb_entries,
                "emails_bound": emails_bound,
            })

        elif path == "/api/admin/announcement":
            ann = game_data.get("announcement", {})
            self.send_json({
                "title": ann.get("title", "欢迎来到滚动的小球"),
                "text": ann.get("text", "如有疑问请联系服主！"),
                "contact": ann.get("contact", ""),
                "enabled": ann.get("enabled", True),
            })

        elif path == "/api/admin/bans":
            bans = game_data.get("bans", {"accounts": [], "ips": [], "uids": []})
            self.send_json({
                "accounts": bans.get("accounts", []),
                "ips": bans.get("ips", []),
                "uids": bans.get("uids", []),
            })

        elif path.startswith("/api/admin/user/"):
            # 单个用户详情：铭文数、铭文清单（含等级聚合）、爆率等
            name = unquote(path[len("/api/admin/user/"):]).strip()
            if name in game_data["users"]:
                u = game_data["users"][name]
                ins = u.get("inscriptions", []) or []
                by_id = {}
                for it in ins:
                    if isinstance(it, dict) and it.get("id"):
                        k = (it["id"], int(it.get("level", 1)))
                        by_id[k] = by_id.get(k, 0) + 1
                inscription_summary = [{"id": i, "level": l, "count": c} for (i, l), c in by_id.items()]
                detail = {
                    "name": name,
                    "uid": u.get("uid", ""),
                    "coins": u.get("coins", 0),
                    "total_score": u.get("total_score", 0),
                    "max_level": u.get("max_level", 1),
                    "email": u.get("email", ""),
                    "last_ip": u.get("last_ip", ""),
                    "reg_ip": u.get("reg_ip", ""),
                    "last_online": int(u.get("last_online", 0) or 0),
                    "drop_rate": float(u.get("drop_rate", 1.0)),
                    "inscription_count": len(ins),
                    "inscriptions": ins,
                    "inscription_summary": inscription_summary,
                    "equipped": u.get("equipped", []),
                    "owned_ball_skins": u.get("owned_ball_skins", []),
                    "owned_bg_skins": u.get("owned_bg_skins", []),
                    "ball_skin": u.get("ball_skin", "default"),
                    "bg_skin": u.get("bg_skin", "default"),
                    "title": u.get("title", "newbie"),
                }
                self.send_json({"ok": True, "user": detail})
            else:
                self.send_json({"error": "用户不存在"})

        else:
            self.send_error(404)

    def handle_admin_post(self, parsed):
        if not self.is_local() and not os.environ.get("ADMIN_REMOTE"):
            self.send_json({"error": "禁止访问：仅限内网"}, status=403)
            return
        # 后台独立限速，防扫描/爆破
        allowed, retry = check_admin_rate_limit(self.get_client_ip())
        if not allowed:
            self.send_json({"error": "请求过于频繁", "retry_after": retry}, 429)
            return
        if not self.check_admin_auth():
            return
        # 串行化写请求，消除并发数据竞争
        with WRITE_LOCK:
            self._handle_admin_post_locked(parsed)

    def _handle_admin_post_locked(self, parsed):
        path = parsed.path
        cl = int(self.headers.get("Content-Length", 0))
        try:
            raw = self.rfile.read(cl).decode("utf-8") if cl > 0 else "{}"
        except UnicodeDecodeError:
            self.send_json({"error": "请求编码无效"}, 400)
            return
        try:
            data = json.loads(raw)
        except Exception:
            data = {}

        if path == "/api/admin/delete_user":
            name = data.get("name", "")
            if name in game_data["users"]:
                del game_data["users"][name]
                # Also remove from leaderboards
                for key in game_data["leaderboards"]:
                    game_data["leaderboards"][key] = [
                        e for e in game_data["leaderboards"][key] if e["name"] != name
                    ]
                save_data(game_data)
                self.send_json({"ok": True, "message": f"已删除用户 {name}"})
            else:
                self.send_json({"error": "用户不存在"})

        elif path == "/api/admin/clear_leaderboard":
            key = data.get("type", "")
            if key in game_data["leaderboards"]:
                game_data["leaderboards"][key] = []
                save_data(game_data)
                self.send_json({"ok": True, "message": f"已清空 {key} 排行榜"})
            else:
                self.send_json({"error": "排行榜类型不存在"})

        elif path == "/api/admin/reset_user_coins":
            name = data.get("name", "")
            if name in game_data["users"]:
                prev = int(game_data["users"][name].get("coins", 0))
                game_data["users"][name]["coins"] = 0
                add_coin_log(game_data["users"][name], -prev, "管理员清零")
                _upsert_leaderboard(name, "coins", 0)
                save_data(game_data)
                self.send_json({"ok": True, "message": f"已重置 {name} 的金币为0"})
            else:
                self.send_json({"error": "用户不存在"})

        elif path == "/api/admin/reset_user_save":
            name = data.get("name", "")
            if name in game_data["users"]:
                game_data["users"][name]["save"] = None
                save_data(game_data)
                self.send_json({"ok": True, "message": f"已清除 {name} 的存档"})
            else:
                self.send_json({"error": "用户不存在"})

        elif path == "/api/admin/set_coins":
            name = data.get("name", "")
            coins = data.get("coins", 0)
            if name in game_data["users"]:
                u = game_data["users"][name]
                prev = int(u.get("coins", 0))
                u["coins"] = int(coins)
                add_coin_log(u, int(coins) - prev, "管理员设置")
                _upsert_leaderboard(name, "coins", u["coins"])
                save_data(game_data)
                self.send_json({"ok": True, "message": f"已设置 {name} 的金币为 {coins}"})
            else:
                self.send_json({"error": "用户不存在"})

        elif path == "/api/admin/update_user":
            name = data.get("name", "")
            if name not in game_data["users"]:
                self.send_json({"error": "用户不存在"})
                return
            user = game_data["users"][name]
            updates = data.get("updates", {})
            # Whitelist of fields the admin can change
            if "password" in updates:
                pwd = updates["password"]
                if isinstance(pwd, str) and 1 <= len(pwd) <= 50:
                    user["password"] = _hash_password(pwd)
            if "email" in updates:
                em = updates["email"]
                if em and not EMAIL_RE.match(em):
                    self.send_json({"error": "邮箱格式不正确"})
                    return
                user["email"] = em
            if "coins" in updates:
                prev = int(user.get("coins", 0))
                user["coins"] = int(updates["coins"])
                add_coin_log(user, int(updates["coins"]) - prev, "管理员更新")
                _upsert_leaderboard(name, "coins", user["coins"])
            if "ball_skin" in updates:
                user["ball_skin"] = updates["ball_skin"]
            if "bg_skin" in updates:
                user["bg_skin"] = updates["bg_skin"]
            if "owned_ball_skins" in updates:
                user["owned_ball_skins"] = updates["owned_ball_skins"]
            if "owned_bg_skins" in updates:
                user["owned_bg_skins"] = updates["owned_bg_skins"]
            if "title" in updates:
                user["title"] = updates["title"]
            if "owned_titles" in updates:
                user["owned_titles"] = updates["owned_titles"]
            if "chat_color" in updates:
                user["chat_color"] = sanitize_chat_color(updates["chat_color"])
            save_data(game_data)
            self.send_json({"ok": True, "message": f"已更新用户 {name} 的信息"})

        elif path == "/api/admin/set_drop_rate":
            # 恶搞：修改单个用户的抽奖爆率倍率（1.0=正常，>1 更易出好东西，<1 更易谢谢参与）
            name = data.get("name", "")
            rate = data.get("rate", None)
            if name not in game_data["users"]:
                self.send_json({"error": "用户不存在"})
                return
            if rate is None:
                self.send_json({"error": "缺少 drop_rate 参数"})
                return
            try:
                rate = float(rate)
            except (TypeError, ValueError):
                self.send_json({"error": "drop_rate 必须是数字"})
                return
            if rate < 0:
                self.send_json({"error": "drop_rate 不能为负"})
                return
            if rate > 100:
                self.send_json({"error": "drop_rate 不能超过 100"})
                return
            game_data["users"][name]["drop_rate"] = rate
            save_data(game_data)
            self.send_json({"ok": True, "message": f"已设置 {name} 的爆率为 {rate}", "drop_rate": rate})

        elif path == "/api/admin/rename_user":
            old_name = data.get("old_name", "")
            new_name = data.get("new_name", "")
            try:
                new_name = sanitize_input(new_name, is_username=True)
            except ValueError:
                self.send_json({"error": "新用户名包含非法内容"})
                return
            if not new_name:
                self.send_json({"error": "新用户名不能为空"})
                return
            if old_name not in game_data["users"]:
                self.send_json({"error": "原用户不存在"})
                return
            if new_name != old_name and new_name in game_data["users"]:
                self.send_json({"error": "该用户名已被占用"})
                return
            if new_name == old_name:
                self.send_json({"ok": True, "message": "用户名未变更"})
                return
            # 与注册一致：禁止改名为受保护的管理员名
            if new_name.lower() in RESERVED_ADMIN_NAMES:
                self.send_json({"error": "该用户名受保护，不可使用"})
                return
            # Rename in users dict (preserve order)
            new_users = {}
            for k, v in game_data["users"].items():
                if k == old_name:
                    new_users[new_name] = v
                else:
                    new_users[k] = v
            game_data["users"] = new_users
            # Rename in leaderboards
            for key in game_data["leaderboards"]:
                for entry in game_data["leaderboards"][key]:
                    if entry["name"] == old_name:
                        entry["name"] = new_name
            # 同步迁移账号级封禁（按名字封的），否则改名后原封禁指向旧名而失效
            bans = game_data.get("bans")
            if isinstance(bans, dict):
                for e in bans.get("accounts", []):
                    if isinstance(e, dict) and e.get("value") == old_name:
                        e["value"] = new_name
            save_data(game_data)
            self.send_json({"ok": True, "message": f"已将 {old_name} 重命名为 {new_name}"})

        elif path == "/api/admin/announcement":
            title = data.get("title", "")
            text = data.get("text", "")
            contact = data.get("contact", "")
            enabled = bool(data.get("enabled", True))
            try:
                if title: title = sanitize_input(title)
                if text: text = sanitize_input(text)
                if contact: contact = sanitize_input(contact)
            except ValueError:
                self.send_json({"error": "公告内容包含非法内容"})
                return
            game_data["announcement"] = {
                "title": (title or "欢迎来到滚动的小球")[:50],
                "text": (text or "如有疑问请联系服主！")[:500],
                "contact": contact[:100],
                "enabled": enabled,
            }
            save_data(game_data)
            self.send_json({"ok": True, "message": "公告已更新"})

        elif path == "/api/admin/ban":
            btype = data.get("type", "")
            value = (data.get("value", "") or "").strip()
            reason = (data.get("reason", "") or "").strip()
            if btype not in ("account", "ip", "uid"):
                self.send_json({"error": "封禁类型无效"})
                return
            if not value:
                self.send_json({"error": "封禁对象不能为空"})
                return
            if btype == "account":
                try:
                    value = sanitize_input(value, is_username=True)
                except ValueError:
                    self.send_json({"error": "账号名包含非法字符"})
                    return
                if value == OWNER_NAME:
                    self.send_json({"error": "不能封禁服主账号"})
                    return
            if btype == "uid" and OWNER_UID and value == OWNER_UID:
                self.send_json({"error": "不能封禁服主设备"})
                return
            if btype == "ip":
                if value in ("127.0.0.1", "::1", "localhost") or \
                   value.startswith(("127.", "192.168.", "10.", "172.16.", "172.17.",
                                     "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                                     "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                                     "172.28.", "172.29.", "172.30.", "172.31.")):
                    self.send_json({"error": "不能封禁内网/本机地址"})
                    return
            # 封禁时长：duration 为秒数；0/空/非法 => 永久封禁
            duration_raw = data.get("duration")
            expires = None
            duration = 0
            if duration_raw:
                try:
                    duration = int(duration_raw)
                    if duration > 0:
                        expires = int(time.time()) + duration
                except (TypeError, ValueError):
                    expires = None
                    duration = 0
            bans = game_data.setdefault("bans", {"accounts": [], "ips": [], "uids": []})
            key = {"account": "accounts", "ip": "ips", "uid": "uids"}[btype]
            existing = [ (e["value"] if isinstance(e, dict) else e) for e in bans[key] ]
            if value not in existing:
                bans[key].append({
                    "value": value,
                    "reason": reason,
                    "at": int(time.time()),
                    "duration": duration,
                    "expires": expires,
                })
                save_data(game_data)
            label = {"account": "账号", "ip": "IP", "uid": "机器"}[btype]
            dur_txt = "" if not expires else f"，{human_duration(duration)}后自动解封"
            self.send_json({"ok": True, "message": f"已封禁{label}：{value}" + (f"（原因：{reason}）" if reason else "") + dur_txt})

        elif path == "/api/admin/unban":
            btype = data.get("type", "")
            value = (data.get("value", "") or "").strip()
            if btype not in ("account", "ip", "uid"):
                self.send_json({"error": "封禁类型无效"})
                return
            if not value:
                self.send_json({"error": "解封对象不能为空"})
                return
            if btype == "account":
                try:
                    value = sanitize_input(value, is_username=True)
                except ValueError:
                    self.send_json({"error": "账号名包含非法字符"})
                    return
            bans = game_data.get("bans", {"accounts": [], "ips": [], "uids": []})
            key = {"account": "accounts", "ip": "ips", "uid": "uids"}[btype]
            before = len(bans[key])
            bans[key] = [ e for e in bans[key] if (e["value"] if isinstance(e, dict) else e) != value ]
            if len(bans[key]) != before:
                save_data(game_data)
                self.send_json({"ok": True, "message": f"已解封：{value}"})
            else:
                self.send_json({"ok": True, "message": f"{value} 不在封禁列表中"})

        else:
            self.send_error(404)

    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        # 限制响应写出超时：避免对端已断开/极慢时 wfile.write 长时间阻塞，
        # 进而无法执行 finally 释放 _conn_per_ip 并发名额。超时后由 do_GET/do_POST
        # 的 except 捕获并释放名额。视频/静态流不走本方法，不受影响。
        conn = getattr(self, "connection", None)
        prev_to = None
        if conn is not None:
            try:
                prev_to = conn.gettimeout()
                conn.settimeout(RESP_SEND_TIMEOUT)
            except Exception:
                pass
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            if conn is not None:
                try:
                    conn.settimeout(prev_to)
                except Exception:
                    pass


if __name__ == "__main__":
    import socket as _socket, sys as _sys, time as _time
    # 单实例保护：若 8080 已被其他实例监听则退出，避免重复实例互相抢端口导致连接被拒
    _probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    _probe.settimeout(1)
    try:
        _probe.connect(("127.0.0.1", PORT))
        print(f"端口 {PORT} 已被占用（game_server 已在运行），本进程退出。")
        _probe.close()
        _sys.exit(0)
    except Exception:
        pass
    finally:
        try:
            _probe.close()
        except Exception:
            pass

    print(f"Game server running on port {PORT}")
    # 后台清理线程：每 60s 自动解封过期的封禁（守护线程，进程退出即止）
    _cleaner = threading.Thread(target=ban_cleaner, daemon=True)
    _cleaner.start()
    _rl_cleaner = threading.Thread(target=rate_limit_cleaner, daemon=True)
    _rl_cleaner.start()
    race_server.start_cleaner()
    # 周期落盘线程：把内存中的 game_data 每 15s 写回 Upstash（云端真源），
    # 防止休眠/重启丢失尚未触发的增量。
    def _flush_loop():
        while True:
            try:
                save_data(game_data)
            except Exception as e:
                print(f"[flush] 保存失败: {e!r}")
            time.sleep(15)
    threading.Thread(target=_flush_loop, daemon=True).start()
    # 管理后台独立绑本机 127.0.0.1:ADMIN_PORT，不暴露公网（frpc 仅转发 8080）
    def _run_admin_server():
        while True:
            try:
                admin_server = ThreadedHTTPServer(("127.0.0.1", ADMIN_PORT), Handler)
                admin_server.serve_forever()
            except Exception as e:
                print(f"[WARN] admin server crashed, restart in 3s: {e!r}")
                time.sleep(3)
    threading.Thread(target=_run_admin_server, daemon=True).start()
    print(f"Admin server (localhost only) running on 127.0.0.1:{ADMIN_PORT}")
    while True:
        try:
            server = ThreadedHTTPServer(("0.0.0.0", PORT), Handler)
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            break
        except Exception as e:
            # 任何未捕获异常都不退出进程，记录后自动重启，避免“老是挂”
            print(f"[WARN] server crashed, restart in 3s: {e!r}")
            try:
                server.shutdown()
            except Exception:
                pass
            _time.sleep(3)
