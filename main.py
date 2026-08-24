import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, Response, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# ------------------------ Configuration ------------------------
CONFIG = {
    "port": int(os.getenv("PORT", 3000)),
    "secret": os.getenv("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

# ------------------------ In‑memory state ------------------------
LINKS: Dict[str, Dict[str, Any]] = {}
SESSIONS: Dict[str, float] = {}
SESSION_TTL = 7 * 24 * 60 * 60  # 1 week
SESSION_COOKIE = "rvg_session"

# ------------------------ Helpers ------------------------
def hash_password(pw: str) -> str:
    return hashlib.sha256((pw + CONFIG["secret"]).encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.getenv("ADMIN_PASSWORD", "123456"))}

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(tok: str | None) -> bool:
    if not tok:
        return False
    exp = SESSIONS.get(tok)
    if not exp or exp < time.time():
        SESSIONS.pop(tok, None)
        return False
    return True

async def destroy_session(tok: str | None):
    if tok:
        SESSIONS.pop(tok, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024**2:
        return f"{b/1024:.1f} KB"
    if b < 1024**3:
        return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def parse_size(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB":
        return int(value * 1024**3)
    if unit == "MB":
        return int(value * 1024**2)
    if unit == "KB":
        return int(value * 1024)
    return int(value)

def is_link_active(l: Dict[str, Any]) -> bool:
    if not l.get("active", True):
        return False
    if l.get("expires_at") and datetime.utcnow() > datetime.fromisoformat(l["expires_at"]):
        return False
    limit = l.get("limit_bytes", 0)
    if limit and l.get("used_bytes", 0) >= limit:
        return False
    return True

def build_sub_headers(label: str, used: int, limit: int, expires: str | None) -> dict:
    total = limit if limit else 0
    exp_ts = 0
    if expires:
        try:
            exp_ts = int(datetime.fromisoformat(expires).timestamp())
        except Exception:
            exp_ts = 0
    userinfo = f"upload=0; download={used}; total={total}; expire={exp_ts}"
    return {
        "profile-title": f"base64:{base64.b64encode(label.encode()).decode()}",
        "subscription-userinfo": userinfo,
        "profile-update-interval": "6",
        "support-url": "https://t.me/CodeBoxo",
    }

def generate_share_link(uuid: str, host: str, remark: str = "RVG", protocol: str = "vless-ws") -> str:
    link = LINKS.get(uuid, {})
    alpn = link.get("alpn", "h2")
    fp = link.get("fingerprint", "chrome")
    if protocol.startswith("trojan"):
        params = {
            "security": "tls",
            "type": "ws" if protocol.endswith("-ws") else "http",
            "host": host,
            "path": f"/trojan{'-ws' if protocol.endswith('-ws') else ''}",
            "sni": host,
            "fp": fp,
            "alpn": alpn,
        }
        q = "&".join(f"{k}={v}" for k, v in params.items())
        return f"trojan://{uuid}@{host}:443?{q}#%{remark}"
    # Default to VLESS‑WS
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": path,
        "sni": host,
        "fp": fp,
        "alpn": alpn,
    }
    q = "&".join(f"{k}={v}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{q}#%{remark}"

# ------------------------ FastAPI app ------------------------
app = FastAPI(title="RVG‑Mini", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------ Endpoints ------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    # A very simple single‑page dashboard (HTML + JS) that handles:
    #   • login (session cookie)
    #   • list existing links (VLESS, Trojan, Shadowsocks…)
    #   • create a new link
    #   • delete a link
    # All API calls are performed with the browser’s fetch API.
    # The page is deliberately lightweight – no external CSS/JS libraries.
    return """
<!doctype html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>RVG Mini Dashboard</title>
<style>
  body {font-family:Arial,Helvetica,sans-serif; margin:20px; background:#f8f9fa;}
  h1 {color:#2c3e50;}
  .section {margin-bottom:30px; padding:15px; background:#fff; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,.1);}
  .link {margin:5px 0; padding:5px; border:1px solid #e0e0e0; border-radius:4px; background:#fafafa;}
  button {cursor:pointer;}
</style>
</head>
<body>
<h1>RVG Mini Dashboard</h1>
<div id='login-section' class='section'>
  <h2>Login</h2>
  <input type='password' id='pwd' placeholder='admin password'>
  <button onclick='login()'>Login</button>
  <p id='login-msg' style='color:red;'></p>
</div>
<div id='dashboard' class='section' style='display:none;'>
  <h2>Create Link</h2>
  <label>Label: <input type='text' id='label'></label><br>
  <label>Protocol: 
    <select id='protocol'>
      <option value='vless-ws'>VLESS (WS)</option>
      <option value='trojan-ws'>Trojan (WS)</option>
      <option value='shadowsocks'>Shadowsocks</option>
    </select>
  </label><br>
  <label>Limit (GB, 0 = unlimited): <input type='number' id='limit' min='0' step='0.1' value='0'></label><br>
  <label>Expire after days (0 = never): <input type='number' id='expire' min='0' value='0'></label><br>
  <button onclick='createLink()'>Create</button>
  <p id='create-msg'></p>

  <h2>Existing Links</h2>
  <div id='links'></div>
</div>
<script>
async function login(){
  const pwd=document.getElementById('pwd').value;
  const resp=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd})});
  if(resp.ok){
    document.getElementById('login-section').style.display='none';
    document.getElementById('dashboard').style.display='block';
    loadLinks();
  } else {
    document.getElementById('login-msg').innerText='Login failed';
  }
}

async function loadLinks(){
  const resp=await fetch('/api/links');
  if(!resp.ok){return;}
  const data=await resp.json();
  const container=document.getElementById('links');
  container.innerHTML='';
  data.links.forEach(l=>{
    const div=document.createElement('div');
    div.className='link';
    div.innerHTML=`<strong>${l.label}</strong> [${l.protocol}]<br>Used: ${l.used_bytes} / ${l.limit_bytes || '∞'} bytes<br>
    <a href='${l.share_link}' target='_blank'>Share Link</a> <button onclick='deleteLink("${l.uuid}")'>Delete</button>`;
    container.appendChild(div);
  });
}

async function createLink(){
  const payload={
    label:document.getElementById('label').value,
    protocol:document.getElementById('protocol').value,
    limit_value:parseFloat(document.getElementById('limit').value),
    limit_unit:'GB',
    expires_days:parseInt(document.getElementById('expire').value)
  };
  const resp=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  if(resp.ok){
    document.getElementById('create-msg').innerText='Link created';
    loadLinks();
  } else {
    const err=await resp.text();
    document.getElementById('create-msg').innerText='Error: '+err;
  }
}

async function deleteLink(uuid){
  if(!confirm('Delete this link?')) return;
  const resp=await fetch('/api/links/'+uuid,{method:'DELETE'});
  if(resp.ok){
    loadLinks();
  } else {
    alert('Delete failed');
  }
}
</script>
</body>
</html>
"""


@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="wrong password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax")
    return resp

@app.post("/api/logout")
async def logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.get("/api/me")
async def me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

# ----- Link management -----
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    data = await request.json()
    uid = generate_uuid()
    label = str(data.get("label", "New Link"))[:60]
    limit_val = float(data.get("limit_value", 0))
    limit_unit = data.get("limit_unit", "GB")
    limit_bytes = parse_size(limit_val, limit_unit) if limit_val > 0 else 0
    expires_days = int(data.get("expires_days", 0))
    expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat() if expires_days else None
    protocol = data.get("protocol", "vless-ws")
    LINK = {
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "created_at": datetime.utcnow().isoformat(),
        "active": True,
        "expires_at": expires_at,
        "protocol": protocol,
        "alpn": "h2,http/1.1",
        "fingerprint": "chrome",
    }
    LINKS[uid] = LINK
    host = CONFIG["host"]
    link_url = generate_share_link(uid, host, remark=label, protocol=protocol)
    return {"uuid": uid, "link": link_url, "data": LINK}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = CONFIG["host"]
    out = []
    for uid, l in LINKS.items():
        out.append({
            "uuid": uid,
            "label": l["label"],
            "active": l["active"],
            "protocol": l["protocol"],
            "used_bytes": l["used_bytes"],
            "limit_bytes": l["limit_bytes"],
            "expires_at": l["expires_at"],
            "share_link": generate_share_link(uid, host, remark=l["label"], protocol=l["protocol"]),
        })
    return {"links": out}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    if uid not in LINKS:
        raise HTTPException(status_code=404, detail="link not found")
    data = await request.json()
    link = LINKS[uid]
    if "label" in data:
        link["label"] = str(data["label"])[:60]
    if "active" in data:
        link["active"] = bool(data["active"])
    if "limit_value" in data:
        lv = float(data["limit_value"])
        lu = data.get("limit_unit", "GB")
        link["limit_bytes"] = parse_size(lv, lu) if lv > 0 else 0
    if "expires_days" in data:
        ed = int(data["expires_days"])
        link["expires_at"] = (datetime.utcnow() + timedelta(days=ed)).isoformat() if ed > 0 else None
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    if uid in LINKS:
        del LINKS[uid]
        return {"ok": True}
    raise HTTPException(status_code=404, detail="link not found")

# ----- Subscriptions -----
@app.get("/sub/{uid}")
async def sub_single(uid: str):
    link = LINKS.get(uid)
    if not link or not is_link_active(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = CONFIG["host"]
    url = generate_share_link(uid, host, remark=link["label"], protocol=link["protocol"])
    content = base64.b64encode(url.encode()).decode()
    hdr = build_sub_headers(link["label"], link["used_bytes"], link["limit_bytes"], link["expires_at"])
    return Response(content=content, media_type="text/plain", headers=hdr)

@app.get("/sub-all")
async def sub_all(_=Depends(require_auth)):
    host = CONFIG["host"]
    lines = []
    total_used = total_limit = 0
    nearest_exp = None
    for uid, l in LINKS.items():
        if not is_link_active(l):
            continue
        lines.append(generate_share_link(uid, host, remark=l["label"], protocol=l["protocol"]))
        total_used += l["used_bytes"]
        total_limit += l["limit_bytes"]
        if l.get("expires_at"):
            if nearest_exp is None or l["expires_at"] < nearest_exp:
                nearest_exp = l["expires_at"]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    hdr = build_sub_headers("RVG‑All", total_used, total_limit, nearest_exp)
    return Response(content=content, media_type="text/plain", headers=hdr)

# ----- Simple stats -----
@app.get("/stats")
async def get_stats(_: Request = None):
    active = sum(1 for l in LINKS.values() if is_link_active(l))
    total_traffic = sum(l["used_bytes"] for l in LINKS.values())
    return {
        "links": len(LINKS),
        "active_links": active,
        "total_traffic_mb": round(total_traffic / 1024**2, 2),
        "uptime": f"{int(time.time())}s",
    }

# -------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
