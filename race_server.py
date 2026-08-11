# -*- coding: utf-8 -*-
"""竞速赛房间系统（独立模块，由 game_server 转发 /api/race/* 请求）。

玩家身份由前端生成 pid（sessionStorage 持久）并随请求带上，后端以 pid 标识玩家。
状态全部在内存（RACES），进程重启即清空——竞速为临时会话，可接受。
"""
import json
import time
import threading
import uuid
import random

RACES = {}
RACE_LOCK = threading.Lock()
RACE_TRACK_LEN = 5000
RACE_MAX_PLAYERS = 8
RACE_EXPIRE = 30 * 60          # 房间空闲过期秒数
RACE_COUNTDOWN = 3.0           # 房主开始后倒计时秒数
RACE_HARD_TIMEOUT = 360        # 比赛开始后硬超时（秒）
RACE_MAX_SPEED_PER_SEC = 400   # 反作弊：赛道推进速度上限(距离单位/秒)，超过按用时钳制可达距离
RACE_SPEED_SLACK = 1.5         # 容许 1.5 倍合理速度，兼容网络抖动/高帧率上报
RACE_MAX_ROOMS = 500           # 反 DoS：内存房间总数上限，超过拒绝新建，防止脚本狂建撑爆内存

# 道具定义：kind=offense 干扰对方, buff 增益自己
ITEMS = {
    "boost":   {"name": "加速", "kind": "buff",    "dur": 2.5},
    "freeze":  {"name": "冰冻", "kind": "offense", "dur": 2.0},
    "reverse": {"name": "反向", "kind": "offense", "dur": 2.5},
    "oil":     {"name": "油渍", "kind": "offense", "dur": 2.5},
    "shield":  {"name": "护盾", "kind": "buff",    "dur": 4.0},
}
ITEM_POOL = list(ITEMS.keys())


def _now():
    return time.time()


def _gen_rid():
    return uuid.uuid4().hex[:8]


def _read_body(self):
    try:
        cl = int(self.headers.get("Content-Length", 0))
    except Exception:
        cl = 0
    raw = b""
    if cl > 0:
        try:
            raw = self.rfile.read(cl)
        except Exception:
            raw = b""
    try:
        return json.loads(raw.decode("utf-8")) if raw else {}
    except Exception:
        return {}


def _send(self, obj, status=200):
    try:
        self.send_json(obj, status)
    except Exception:
        pass


def _active_debuffs(p):
    """返回玩家当前生效的 debuff 类型列表"""
    t = _now()
    out = []
    for k, exp in (p.get("debuffs") or {}).items():
        if exp > t:
            out.append(k)
    return out


def _make_room(host_pid, host_name, host_uid):
    return {
        "id": _gen_rid(),
        "host": host_pid,
        "track_len": RACE_TRACK_LEN,
        "phase": "waiting",          # waiting -> countdown -> racing -> finished
        "players": {},
        "created": _now(),
        "last_active": _now(),
        "countdown_end": 0,
        "start_time": 0,
        "events": [],
        "event_seq": 0,
        "result": None,
    }


def _add_event(room, ev):
    room["event_seq"] += 1
    ev = dict(ev)
    ev["seq"] = room["event_seq"]
    ev["t"] = _now()
    room["events"].append(ev)
    if len(room["events"]) > 120:   # 仅保留最近 120 条，避免无限增长
        room["events"] = room["events"][-120:]
    return ev


def _join_player(room, pid, name, uid):
    # 同账号（已登录同名）跨设备/浏览器去重：移除房间内同名的其他玩家条目
    if name:
        for opid in list(room["players"].keys()):
            if opid != pid and room["players"][opid].get("name") == name:
                del room["players"][opid]
    if pid not in room["players"]:
        room["players"][pid] = {
            "pid": pid,
            "name": name or "玩家",
            "uid": uid or "",
            "distance": 0,
            "finished": False,
            "finish_time": 0,
            "items": [],
            "last_seen": _now(),
            "debuffs": {},
        }
    else:
        room["players"][pid]["name"] = name or room["players"][pid]["name"]
        room["players"][pid]["last_seen"] = _now()
    return room["players"][pid]


def _public_players(room):
    """已完成的按完成时间升序在前，未完成的按 distance 降序在后"""
    finished = [p for p in room["players"].values() if p["finished"]]
    unfinished = [p for p in room["players"].values() if not p["finished"]]
    finished.sort(key=lambda p: p["finish_time"])
    unfinished.sort(key=lambda p: p["distance"], reverse=True)
    out = []
    for rank, p in enumerate(finished + unfinished, 1):
        out.append({
            "pid": p["pid"],
            "name": p["name"],
            "distance": round(p["distance"], 1),
            "finished": p["finished"],
            "rank": rank,
            "is_host": p["pid"] == room["host"],
            "debuffs": _active_debuffs(p),
            "items": p["items"],        # 休闲游戏，下发无妨
        })
    return out


def _check_phase_transition(room):
    t = _now()
    if room["phase"] == "countdown" and t >= room["countdown_end"]:
        room["phase"] = "racing"
        room["start_time"] = t
        _add_event(room, {"type": "phase", "phase": "racing"})
    if room["phase"] == "racing":
        all_done = room["players"] and all(p["finished"] for p in room["players"].values())
        timeout = t - room["start_time"] > RACE_HARD_TIMEOUT
        if all_done or timeout:
            _finish_room(room)


def _finish_room(room):
    room["phase"] = "finished"
    _add_event(room, {"type": "phase", "phase": "finished"})
    finished = [p for p in room["players"].values() if p["finished"]]
    unfinished = [p for p in room["players"].values() if not p["finished"]]
    finished.sort(key=lambda p: p["finish_time"])
    unfinished.sort(key=lambda p: p["distance"], reverse=True)
    ranking = []
    for rank, p in enumerate(finished + unfinished, 1):
        ranking.append({"rank": rank, "pid": p["pid"], "name": p["name"],
                        "finished": p["finished"], "distance": round(p["distance"], 1)})
    room["result"] = ranking


# ===================== HTTP entry =====================
def handle_race(self, parsed, data=None):
    if data is None:
        data = _read_body(self)
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 3:
        return _send(self, {"error": "invalid path"}, 400)
    sub = parts[2]
    with RACE_LOCK:
        if sub == "create":
            return _race_create(self, data)
        if sub == "match":
            return _race_match(self, data)
        if sub == "join":
            return _race_join(self, data)
        room = RACES.get(sub)
        if room is None:
            return _send(self, {"error": "房间不存在或已过期"}, 404)
        room["last_active"] = _now()
        action = parts[3] if len(parts) > 3 else ""
        if action == "progress":
            return _race_progress(self, room, data)
        if action == "item":
            return _race_item(self, room, data)
        if action == "pick":
            return _race_pick(self, room, data)
        if action == "start":
            return _race_start(self, room, data)
        if action == "leave":
            return _race_leave(self, room, data)
        return _send(self, {"error": "unknown action"}, 400)


def handle_race_get(self, parsed):
    from urllib.parse import parse_qs
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 3:
        return _send(self, {"error": "invalid path"}, 400)
    qs = parse_qs(parsed.query)
    rid = parts[2]
    pid = qs.get("pid", [""])[0]
    try:
        last_seq = int(qs.get("seq", ["0"])[0] or 0)
    except Exception:
        last_seq = 0
    with RACE_LOCK:
        room = RACES.get(rid)
        if room is None:
            return _send(self, {"error": "房间不存在或已过期"}, 404)
        room["last_active"] = _now()
        _check_phase_transition(room)
        new_events = [e for e in room["events"] if e["seq"] > last_seq]
        resp = {
            "room_id": room["id"],
            "phase": room["phase"],
            "track_len": room["track_len"],
            "host": room["host"],
            "you": pid,
            "players": _public_players(room),
            "events": new_events,
            "result": room["result"],
        }
        if room["phase"] == "countdown":
            resp["countdown_left"] = max(0, round(room["countdown_end"] - _now(), 1))
        if room["phase"] == "racing":
            resp["elapsed"] = round(_now() - room["start_time"], 1)
        _send(self, resp)


# ===================== actions =====================
def _race_create(self, data):
    # 反 DoS：房间总数上限，防止脚本狂建房间撑爆内存
    if len(RACES) >= RACE_MAX_ROOMS:
        return _send(self, {"error": "房间数已达上限，请稍后再试"}, 503)
    pid = (data.get("pid") or "").strip() or uuid.uuid4().hex[:10]
    name = (data.get("name") or "玩家").strip()[:20]
    uid = data.get("uid") or ""
    room = _make_room(pid, name, uid)
    _join_player(room, pid, name, uid)
    RACES[room["id"]] = room
    _add_event(room, {"type": "join", "from": pid, "name": name})
    _send(self, {"ok": True, "room_id": room["id"], "pid": pid, "host": True,
                 "track_len": room["track_len"], "phase": room["phase"]})


def _race_match(self, data):
    # 反 DoS：房间总数上限，防止脚本狂建房间撑爆内存
    if len(RACES) >= RACE_MAX_ROOMS:
        return _send(self, {"error": "房间数已达上限，请稍后再试"}, 503)
    pid = (data.get("pid") or "").strip() or uuid.uuid4().hex[:10]
    name = (data.get("name") or "玩家").strip()[:20]
    uid = data.get("uid") or ""
    target = None
    for r in RACES.values():
        if r["phase"] == "waiting" and len(r["players"]) < RACE_MAX_PLAYERS:
            target = r
            break
    if target is None:
        target = _make_room(pid, name, uid)
        RACES[target["id"]] = target
    _join_player(target, pid, name, uid)
    _add_event(target, {"type": "join", "from": pid, "name": name})
    _send(self, {"ok": True, "room_id": target["id"], "pid": pid,
                 "host": pid == target["host"], "track_len": target["track_len"],
                 "phase": target["phase"]})


def _race_join(self, data):
    rid = (data.get("room_id") or "").strip()
    if not rid:
        return _send(self, {"error": "缺少房间号"}, 400)
    room = RACES.get(rid)
    if room is None:
        return _send(self, {"error": "房间不存在或已过期"}, 404)
    if room["phase"] != "waiting":
        return _send(self, {"error": "房间已开始，无法加入"}, 409)
    if len(room["players"]) >= RACE_MAX_PLAYERS:
        return _send(self, {"error": "房间已满"}, 409)
    pid = (data.get("pid") or "").strip() or uuid.uuid4().hex[:10]
    name = (data.get("name") or "玩家").strip()[:20]
    uid = data.get("uid") or ""
    _join_player(room, pid, name, uid)
    _add_event(room, {"type": "join", "from": pid, "name": name})
    _send(self, {"ok": True, "room_id": room["id"], "pid": pid,
                 "host": pid == room["host"], "track_len": room["track_len"],
                 "phase": room["phase"]})


def _race_start(self, room, data):
    pid = data.get("pid") or ""
    if pid != room["host"]:
        return _send(self, {"error": "只有房主可以开始"}, 403)
    if room["phase"] != "waiting":
        return _send(self, {"error": "比赛已开始"}, 409)
    room["phase"] = "countdown"
    room["countdown_end"] = _now() + RACE_COUNTDOWN
    _add_event(room, {"type": "phase", "phase": "countdown"})
    _send(self, {"ok": True, "phase": "countdown", "countdown": RACE_COUNTDOWN})


def _race_progress(self, room, data):
    pid = data.get("pid") or ""
    p = room["players"].get(pid)
    if p is None:
        return _send(self, {"error": "你不在房间内"}, 404)
    p["last_seen"] = _now()
    # 确保倒计时→进行中 状态翻转（原本仅靠 GET 轮询触发；若客户端只 POST 不 GET
    # 会卡在 countdown 导致位移被忽略。此处主动触发，行为更健壮）。
    _check_phase_transition(room)
    # 反作弊：仅在比赛进行中("racing")接受位移；倒计时/等待/已结束阶段忽略，
    # 防止玩家在倒计时阶段就预设巨大 distance。
    if room["phase"] != "racing":
        _send(self, {"ok": True})
        return
    try:
        d = float(data.get("distance", 0) or 0)
    except Exception:
        d = 0
    # 钳制到合法范围 [0, track_len]，杜绝 distance 超界(如 999999)扰乱排名
    if d < 0:
        d = 0
    if d > room["track_len"]:
        d = room["track_len"]
    # 反作弊：按比赛已用时限制“最大可达距离”。任何上报都不得超过
    #   track_len × min(1, 速度上限×已用时×冗余) ，
    # 这彻底杜绝“首包 distance=5000 直接秒杀夺冠”的客户端作弊。
    elapsed = _now() - room.get("start_time", _now())
    if elapsed < 0:
        elapsed = 0
    max_allowed = min(room["track_len"], RACE_MAX_SPEED_PER_SEC * elapsed * RACE_SPEED_SLACK)
    if d > max_allowed:
        d = max_allowed
    if d > p["distance"]:
        p["distance"] = d
    # finished 由服务端按“到达终点”判定，忽略客户端 finished 标志，防止伪造通关
    if not p["finished"] and p["distance"] >= room["track_len"]:
        p["finished"] = True
        p["finish_time"] = _now()
        _add_event(room, {"type": "finish", "from": pid, "name": p["name"]})
        _check_phase_transition(room)
    _send(self, {"ok": True})


def _race_pick(self, room, data):
    pid = data.get("pid") or ""
    p = room["players"].get(pid)
    if p is None:
        return _send(self, {"error": "你不在房间内"}, 404)
    if len(p["items"]) >= 3:
        return _send(self, {"ok": True, "items": p["items"], "full": True})
    item = random.choice(ITEM_POOL)
    p["items"].append(item)
    _add_event(room, {"type": "pick", "from": pid, "item": item})
    _send(self, {"ok": True, "items": p["items"]})


def _race_item(self, room, data):
    pid = data.get("pid") or ""
    p = room["players"].get(pid)
    if p is None:
        return _send(self, {"error": "你不在房间内"}, 404)
    if room["phase"] != "racing":
        return _send(self, {"error": "比赛未开始"}, 409)
    item = data.get("item") or ""
    if item not in ITEMS:
        return _send(self, {"error": "未知道具"}, 400)
    if item not in p["items"]:
        return _send(self, {"error": "你没有该道具"}, 400)
    info = ITEMS[item]
    target_pid = data.get("target") or pid
    if info["kind"] == "offense":
        if target_pid == pid:
            return _send(self, {"error": "不能对自己使用干扰道具"}, 400)
        tp = room["players"].get(target_pid)
        if tp is None:
            return _send(self, {"error": "目标不存在"}, 404)
        if (tp.get("debuffs") or {}).get("shield", 0) > _now():
            return _send(self, {"error": "对方有护盾，免疫干扰"}, 409)
        tp.setdefault("debuffs", {})[item] = _now() + info["dur"]
    else:
        p.setdefault("debuffs", {})[item] = _now() + info["dur"]
    p["items"].remove(item)
    _add_event(room, {"type": "item", "from": pid, "to": target_pid,
                     "item": item, "kind": info["kind"]})
    _send(self, {"ok": True, "items": p["items"]})


def _race_leave(self, room, data):
    pid = data.get("pid") or ""
    if pid in room["players"]:
        del room["players"][pid]
        _add_event(room, {"type": "leave", "from": pid})
    if not room["players"]:
        RACES.pop(room["id"], None)
    elif pid == room["host"]:
        room["host"] = next(iter(room["players"].keys()))
    _send(self, {"ok": True})


# ===================== background cleanup =====================
def start_cleaner():
    def loop():
        while True:
            time.sleep(60)
            try:
                _clean()
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()


def _clean():
    t = _now()
    with RACE_LOCK:
        expired = []
        for rid, room in RACES.items():
            idle = t - room["last_active"] > RACE_EXPIRE
            stale_finished = room["phase"] == "finished" and (t - room.get("start_time", t)) > 600
            if idle or stale_finished:
                expired.append(rid)
        for rid in expired:
            RACES.pop(rid, None)
