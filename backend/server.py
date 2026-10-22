from dotenv import load_dotenv
load_dotenv()

import os
import re
import uuid
import logging
import ipaddress
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import bcrypt
import jwt
import httpx
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from pydantic import BaseModel, Field
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# Swagger fica desligado em produção; ENABLE_DOCS=true reativa
_docs = os.environ.get("ENABLE_DOCS", "false").lower() == "true"
app = FastAPI(title="MAF API",
              docs_url="/api/docs" if _docs else None,
              redoc_url=None,
              openapi_url="/api/openapi.json" if _docs else None)
api_router = APIRouter(prefix="/api")

JWT_ALGORITHM = "HS256"

EMAIL_BASE_URL = "https://integrations.emergentagent.com"
EMAIL_KEY = os.environ.get("EMERGENT_EMAIL_KEY")
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "MAF — Mundos Artificiais em Finanças")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL")

logger = logging.getLogger(__name__)


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "type": "access",
               "exp": datetime.now(timezone.utc) + timedelta(minutes=60)}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id, "type": "refresh",
               "exp": datetime.now(timezone.utc) + timedelta(days=7)}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
# Front e API no mesmo domínio (via Nginx): Lax basta e protege contra CSRF
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "lax").lower()


def set_auth_cookies(response: Response, access: str, refresh: str):
    response.set_cookie("access_token", access, httponly=True, secure=COOKIE_SECURE,
                        samesite=COOKIE_SAMESITE, max_age=3600, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=COOKIE_SECURE,
                        samesite=COOKIE_SAMESITE, max_age=604800, path="/")


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ---------- Email (Emergent managed Resend) ----------

_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)


class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan(); scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks the recipient for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links/assets must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Shortened, numeric-host or credential-bearing URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text {m.group(1)!r} != real link host {real!r} (G3)")


async def send_email(*, to: str, subject: str, html: str, reply_to: Optional[str] = None) -> Optional[str]:
    _assert_safe_email(subject, html)
    payload = {"to": [to], "subject": subject, "html": html, "from_name": EMAIL_FROM_NAME}
    if reply_to:
        payload["contact_email"] = reply_to
    try:
        async with httpx.AsyncClient(timeout=30) as http:
            resp = await http.post(
                f"{EMAIL_BASE_URL}/api/v1/email/send",
                headers={"X-Email-Key": EMAIL_KEY},
                json=payload,
            )
        resp.raise_for_status()
        return resp.json().get("id")
    except httpx.HTTPStatusError as e:
        try:
            code = e.response.json().get("code", "")
        except ValueError:
            code = ""
        if code in ("insufficient_credits", "integration_disabled", "daily_limit_reached"):
            logger.warning(f"Email paused: {code} ({e.response.status_code})")
            raise HTTPException(status_code=503, detail="Email is temporarily unavailable")
        logger.error(f"Email send failed: {e.response.status_code} {e.response.text}")
        raise HTTPException(status_code=502, detail="Failed to send email")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email send error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send email")


# ---------- Models ----------

class LoginInput(BaseModel):
    email: str
    password: str


class PublicationIn(BaseModel):
    title: str
    authors: str
    venue: str
    year: int
    tags: List[str] = []
    url: Optional[str] = None
    kind: str = "article"
    published: bool = True


class Publication(PublicationIn):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class NewsIn(BaseModel):
    title_pt: str
    title_en: str
    summary_pt: str
    summary_en: str
    date: str
    tag: str = "LAB"
    featured: bool = False
    image_url: Optional[str] = None
    published: bool = True


class News(NewsIn):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class ContactIn(BaseModel):
    name: str
    email: str
    subject: str
    category: str = "pesquisa"
    message: str


class ContactStatusIn(BaseModel):
    status: str


class ReplyIn(BaseModel):
    text: str


class TeamMemberIn(BaseModel):
    name: str
    role_pt: str = ""
    role_en: str = ""
    institution: str = ""
    group: str = "ufrj"
    areas_pt: List[str] = []
    areas_en: List[str] = []
    education: List[str] = []
    bio_pt: str = ""
    bio_en: str = ""
    highlight_pt: str = ""
    highlight_en: str = ""
    lattes: Optional[str] = None
    orcid: Optional[str] = None
    linkedin: Optional[str] = None
    photo_url: Optional[str] = None
    published: bool = True
    order: int = 0


class TeamMember(TeamMemberIn):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ---------- Auth ----------

async def check_lockout(identifier: str):
    rec = await db.login_attempts.find_one({"identifier": identifier})
    if rec and rec.get("count", 0) >= 5:
        locked_until = rec.get("locked_until")
        if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
            raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")


async def record_failure(identifier: str):
    rec = await db.login_attempts.find_one({"identifier": identifier})
    count = (rec.get("count", 0) + 1) if rec else 1
    doc = {"identifier": identifier, "count": count,
           "last_attempt": datetime.now(timezone.utc).isoformat()}
    if count >= 5:
        doc["locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    await db.login_attempts.update_one({"identifier": identifier}, {"$set": doc}, upsert=True)


@api_router.post("/auth/login")
async def login(input: LoginInput, request: Request, response: Response):
    email = input.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"
    await check_lockout(identifier)
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(input.password, user["password_hash"]):
        await record_failure(identifier)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    await db.login_attempts.delete_many({"identifier": identifier})
    set_auth_cookies(response, create_access_token(user["id"], email), create_refresh_token(user["id"]))
    return {"id": user["id"], "email": email, "name": user.get("name", "Admin"), "role": user.get("role", "admin")}


@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api_router.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    response.set_cookie("access_token", create_access_token(user["id"], user["email"]),
                        httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, max_age=3600, path="/")
    return user


class GoogleSessionIn(BaseModel):
    session_id: str


@api_router.post("/auth/google")
async def google_auth(input: GoogleSessionIn, response: Response):
    async with httpx.AsyncClient(timeout=20) as http:
        r = await http.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": input.session_id},
        )
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid Google session")
    data = r.json()
    email = (data.get("email") or "").lower()
    allowed = os.environ.get("ADMIN_EMAIL", "").lower()
    if not email or email != allowed:
        raise HTTPException(status_code=403, detail="This Google account is not authorized for the admin panel")
    user = await db.users.find_one({"email": email})
    if not user:
        user = {
            "id": str(uuid.uuid4()), "email": email, "name": data.get("name", "Admin"),
            "picture": data.get("picture"), "role": "admin", "password_hash": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.users.insert_one(user)
    else:
        await db.users.update_one({"email": email},
                                  {"$set": {"name": data.get("name"), "picture": data.get("picture")}})
    set_auth_cookies(response, create_access_token(user["id"], email), create_refresh_token(user["id"]))
    return {"id": user["id"], "email": email, "name": data.get("name", "Admin"), "role": "admin"}


# ---------- Publications ----------

@api_router.get("/publications", response_model=List[Publication])
async def list_publications():
    return await db.publications.find({"published": {"$ne": False}}, {"_id": 0}).sort("year", -1).to_list(500)


@api_router.get("/admin/publications", response_model=List[Publication])
async def admin_list_publications(user: dict = Depends(get_current_user)):
    return await db.publications.find({}, {"_id": 0}).sort("year", -1).to_list(500)


@api_router.post("/publications", response_model=Publication)
async def create_publication(input: PublicationIn, user: dict = Depends(get_current_user)):
    pub = Publication(**input.model_dump())
    await db.publications.insert_one(pub.model_dump())
    return pub


@api_router.put("/publications/{pub_id}", response_model=Publication)
async def update_publication(pub_id: str, input: PublicationIn, user: dict = Depends(get_current_user)):
    res = await db.publications.update_one({"id": pub_id}, {"$set": input.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Publication not found")
    doc = await db.publications.find_one({"id": pub_id}, {"_id": 0})
    return Publication(**doc)


@api_router.delete("/publications/{pub_id}")
async def delete_publication(pub_id: str, user: dict = Depends(get_current_user)):
    res = await db.publications.delete_one({"id": pub_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Publication not found")
    return {"ok": True}


# ---------- News ----------

@api_router.get("/news", response_model=List[News])
async def list_news():
    return await db.news.find({"published": {"$ne": False}}, {"_id": 0}).sort("date", -1).to_list(200)


@api_router.get("/admin/news", response_model=List[News])
async def admin_list_news(user: dict = Depends(get_current_user)):
    return await db.news.find({}, {"_id": 0}).sort("date", -1).to_list(200)


@api_router.post("/news", response_model=News)
async def create_news(input: NewsIn, user: dict = Depends(get_current_user)):
    item = News(**input.model_dump())
    await db.news.insert_one(item.model_dump())
    return item


@api_router.put("/news/{news_id}", response_model=News)
async def update_news(news_id: str, input: NewsIn, user: dict = Depends(get_current_user)):
    res = await db.news.update_one({"id": news_id}, {"$set": input.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="News not found")
    doc = await db.news.find_one({"id": news_id}, {"_id": 0})
    return News(**doc)


@api_router.delete("/news/{news_id}")
async def delete_news(news_id: str, user: dict = Depends(get_current_user)):
    res = await db.news.delete_one({"id": news_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="News not found")
    return {"ok": True}


# ---------- Team ----------

@api_router.get("/team", response_model=List[TeamMember])
async def list_team():
    return await db.team_members.find({"published": {"$ne": False}}, {"_id": 0}).sort("order", 1).to_list(100)


@api_router.get("/admin/team", response_model=List[TeamMember])
async def admin_list_team(user: dict = Depends(get_current_user)):
    return await db.team_members.find({}, {"_id": 0}).sort("order", 1).to_list(100)


@api_router.post("/team", response_model=TeamMember)
async def create_team_member(input: TeamMemberIn, user: dict = Depends(get_current_user)):
    member = TeamMember(**input.model_dump())
    await db.team_members.insert_one(member.model_dump())
    return member


@api_router.put("/team/{member_id}", response_model=TeamMember)
async def update_team_member(member_id: str, input: TeamMemberIn, user: dict = Depends(get_current_user)):
    res = await db.team_members.update_one({"id": member_id}, {"$set": input.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Team member not found")
    doc = await db.team_members.find_one({"id": member_id}, {"_id": 0})
    return TeamMember(**doc)


@api_router.delete("/team/{member_id}")
async def delete_team_member(member_id: str, user: dict = Depends(get_current_user)):
    res = await db.team_members.delete_one({"id": member_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Team member not found")
    return {"ok": True}


# ---------- Contact ----------

def contact_email_html(input: ContactIn) -> str:
    row = "padding:6px 0;font-size:14px;color:#1e293b"
    label = "font-family:monospace;font-size:11px;color:#10b981;text-transform:uppercase;letter-spacing:2px"
    return (
        '<table role="presentation" width="100%" style="background:#07090e;padding:32px 0"><tr><td align="center">'
        '<table role="presentation" width="560" style="background:#0d1117;border:1px solid rgba(255,255,255,0.1);'
        'border-radius:12px;padding:28px;font-family:Arial,sans-serif">'
        f'<tr><td style="{label}">MAF · Mundos Artificiais em Finanças</td></tr>'
        f'<tr><td style="padding:10px 0 18px;font-size:20px;font-weight:bold;color:#f8fafc">Nova mensagem de contato</td></tr>'
        f'<tr><td style="{row}"><strong style="color:#94a3b8">Nome:</strong> {escape(input.name)}</td></tr>'
        f'<tr><td style="{row}"><strong style="color:#94a3b8">E-mail:</strong> {escape(input.email)}</td></tr>'
        f'<tr><td style="{row}"><strong style="color:#94a3b8">Categoria:</strong> {escape(input.category)}</td></tr>'
        f'<tr><td style="{row}"><strong style="color:#94a3b8">Assunto:</strong> {escape(input.subject)}</td></tr>'
        f'<tr><td style="{row};white-space:pre-wrap">{escape(input.message)}</td></tr>'
        f'<tr><td style="padding-top:20px;font-size:11px;color:#64748b">Enviado pelo site {escape(EMAIL_FROM_NAME)} · UFRJ/PPGI · CEFET/RJ</td></tr>'
        "</table></td></tr></table>"
    )


def reply_email_html(msg: dict, text: str) -> str:
    row = "padding:6px 0;font-size:14px;color:#e2e8f0"
    label = "font-family:monospace;font-size:11px;color:#10b981;text-transform:uppercase;letter-spacing:2px"
    return (
        '<table role="presentation" width="100%" style="background:#07090e;padding:32px 0"><tr><td align="center">'
        '<table role="presentation" width="560" style="background:#0d1117;border:1px solid rgba(255,255,255,0.1);'
        'border-radius:12px;padding:28px;font-family:Arial,sans-serif">'
        f'<tr><td style="{label}">MAF · Mundos Artificiais em Finanças</td></tr>'
        f'<tr><td style="padding:10px 0 16px;font-size:20px;font-weight:bold;color:#f8fafc">Olá, {escape(msg.get("name", ""))}!</td></tr>'
        f'<tr><td style="{row};white-space:pre-wrap">{escape(text)}</td></tr>'
        f'<tr><td style="padding:18px 0 6px;font-size:12px;color:#64748b">Em referência à sua mensagem: '
        f'<em style="color:#94a3b8">{escape(msg.get("subject", ""))}</em></td></tr>'
        f'<tr><td style="padding-top:16px;font-size:11px;color:#64748b">{escape(EMAIL_FROM_NAME)} · UFRJ/PPGI · CEFET/RJ — '
        'nunca pedimos senhas ou dados de pagamento por e-mail.</td></tr>'
        "</table></td></tr></table>"
    )


@api_router.post("/contact")
async def send_contact(input: ContactIn):
    doc = input.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["status"] = "new"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.contacts.insert_one(doc)
    if NOTIFY_EMAIL and EMAIL_KEY:
        try:
            await send_email(
                to=NOTIFY_EMAIL,
                subject=f"[MAF] Contato: {escape(input.subject)[:80]}",
                html=contact_email_html(input),
            )
        except Exception as e:
            logger.warning(f"Contact notification email not sent: {e}")
    return {"ok": True, "id": doc["id"]}


@api_router.get("/contact")
async def list_contacts(user: dict = Depends(get_current_user)):
    return await db.contacts.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.patch("/contact/{msg_id}")
async def set_contact_status(msg_id: str, input: ContactStatusIn, user: dict = Depends(get_current_user)):
    if input.status not in ("new", "replied"):
        raise HTTPException(status_code=400, detail="Invalid status")
    res = await db.contacts.update_one({"id": msg_id}, {"$set": {"status": input.status}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Message not found")
    return {"ok": True}


@api_router.post("/contact/{msg_id}/reply")
async def reply_contact(msg_id: str, input: ReplyIn, user: dict = Depends(get_current_user)):
    msg = await db.contacts.find_one({"id": msg_id}, {"_id": 0})
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if not EMAIL_KEY:
        raise HTTPException(status_code=503, detail="Email integration unavailable")
    await send_email(
        to=msg["email"],
        subject="MAF — Mundos Artificiais em Finanças: retorno ao seu contato",
        html=reply_email_html(msg, input.text),
    )
    await db.contacts.update_one({"id": msg_id}, {"$set": {
        "status": "replied",
        "replied_at": datetime.now(timezone.utc).isoformat(),
        "reply_text": input.text,
    }})
    return {"ok": True}


@api_router.delete("/contact/{msg_id}")
async def delete_contact(msg_id: str, user: dict = Depends(get_current_user)):
    res = await db.contacts.delete_one({"id": msg_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Message not found")
    return {"ok": True}


@api_router.get("/admin/stats")
async def admin_stats(user: dict = Depends(get_current_user)):
    return {
        "publications": await db.publications.count_documents({}),
        "news": await db.news.count_documents({}),
        "messages": await db.contacts.count_documents({}),
    }


@api_router.get("/")
async def root():
    return {"message": "MAF API — Mundos Artificiais em Finanças"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Seeds ----------

async def seed_admin():
    email = os.environ.get("ADMIN_EMAIL", "").lower()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not email or len(password) < 12:
        raise RuntimeError("ADMIN_EMAIL e ADMIN_PASSWORD (mín. 12 caracteres) são obrigatórios")
    existing = await db.users.find_one({"email": email})
    if existing is None:
        await db.users.insert_one({
            "id": str(uuid.uuid4()), "email": email, "name": "Administrador MAF",
            "role": "admin", "password_hash": hash_password(password),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    elif not existing.get("password_hash") or not verify_password(password, existing["password_hash"]):
        await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_password(password)}})


IMG_ORDERBOOK = "https://images.unsplash.com/photo-1689732888407-310424e3a372?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwyfHxhYnN0cmFjdCUyMGRhdGElMjB2aXN1YWxpemF0aW9uJTIwZmluYW5jaWFsJTIwbmV0d29yayUyMGRhcmt8ZW58MHx8fHwxNzkxOTkyODAxfDA&ixlib=rb-4.1.0&q=85"
IMG_MESH = "https://images.unsplash.com/photo-1644088379091-d574269d422f?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMzV8MHwxfHNlYXJjaHwxfHxhYnN0cmFjdCUyMGRhdGElMjB2aXN1YWxpemF0aW9uJTIwZmluYW5jaWFsJTIwbmV0d29yayUyMGRhcmt8ZW58MHx8fHwxNzkxOTkyODAxfDA&ixlib=rb-4.1.0&q=85"
IMG_NEURAL = "https://images.unsplash.com/photo-1674027444485-cec3da58eef4?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA3MDB8MHwxfHNlYXJjaHwxfHxhcnRpZmljaWFsJTIwaW50ZWxsaWdlbmNlJTIwZGFyayUyMG1lc2glMjBuZXR3b3JrfGVufDB8fHx8MTc4NjEyMDY5MHww&ixlib=rb-4.1.0&q=85"
IMG_RESEARCH = "https://images.unsplash.com/photo-1544280124-2f0a80ccee73?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NDk1Nzh8MHwxfHNlYXJjaHwzfHxyZXNlYXJjaGVyJTIwc2NpZW50aXN0JTIwdGhpbmtpbmclMjBwb3J0cmFpdHxlbnwwfHx8fDE3OTE5OTI4MjF8MA&ixlib=rb-4.1.0&q=85"

SEED_PUBLICATIONS = [
    {"title": "Um Estudo Utilizando Fatos Estilizados na Comparação entre FIIs e REITs",
     "authors": "PASSOS, G. G. F. G.; RIBEIRO, S. A.; SCHMITZ, E. A.",
     "venue": "Anais do XXV Encontro Brasileiro de Finanças", "year": 2025,
     "tags": ["ABMS", "Mercados Artificiais"], "kind": "conference"},
    {"title": "Simulação Baseada em Agentes e Indicadores em ILPIs: Um Estudo para o Desenvolvimento do GeronTrack",
     "authors": "SANTOS, R. O.; FERREIRA, E.; FUSCHILO, C.",
     "venue": "Anais do XIX WESAAC — Workshop-Escola de Sistemas de Agentes, seus Ambientes e Aplicações", "year": 2025,
     "tags": ["ABMS", "Simulação"], "kind": "conference"},
    {"title": "Modeling the COVID-19 vaccination process using the FRAM Method",
     "authors": "AMARAL NETO, A. S.; NASCIMENTO, N. M.; LOUREIRO, A. B.; SILVA, M. F.; ARAÚJO, C.; RUBIO, M. P. A.; RIBEIRO, S. A.",
     "venue": "Ciência & Saúde Coletiva, v. 30", "year": 2025,
     "tags": ["Simulação", "Modelagem"], "kind": "article"},
    {"title": "Relatos sobre a criação da primeira olimpíada com foco em investimentos no Brasil",
     "authors": "PASSOS, G. G. F. G.",
     "venue": "Revista de Extensão", "year": 2023,
     "tags": ["Educação Financeira", "OBInvest"], "kind": "article"},
    {"title": "Risk Factors in the Software Deployment Phase: A Case Study Applied in two Brazilian Government Companies",
     "authors": "DOS SANTOS, L. J.; RIBEIRO, S. A.; SCHMITZ, E. A.; SILVA, M. F.; DE ALENCAR, A. J. S. M.",
     "venue": "Revista de Gestão da Tecnologia e Sistemas de Informação (JISTEM), v. 19", "year": 2022,
     "tags": ["Engenharia de Software", "Risco"], "kind": "article"},
    {"title": "Facilitators and barriers that influence Nursing Professionals in the Adoption of Information Systems: a systematic review",
     "authors": "AMARAL NETO, A. S.; ALVES, R. M. B.; SILVA, M. F.; SCHMITZ, E. A.; JUAREZ ALENCAR, A.",
     "venue": "iSys — Revista Brasileira de Sistemas de Informação, v. 15", "year": 2022,
     "tags": ["Sistemas de Informação"], "kind": "article"},
    {"title": "A Dynamic Job Shop Model for Scheduling Tasks in a Software Development Environment",
     "authors": "RIBEIRO, S. A.; SCHMITZ, E. A.; SILVA, M. F.; ALENCAR, A. J.",
     "venue": "Revista de Gestão da Tecnologia e Sistemas de Informação, v. 18", "year": 2021,
     "tags": ["Otimização", "Simulação"], "kind": "article"},
    {"title": "Uma Proposta para Seleção de Portfólios Eficientes Utilizando Análise Envoltória de Dados (DEA)",
     "authors": "FUSCHILO, C.; SCHMITZ, E. A.; FEIJÓ, M.",
     "venue": "18th CONTECSI — International Conference on Information Systems and Technology Management", "year": 2021,
     "tags": ["Finanças Quantitativas", "DEA"], "kind": "conference"},
    {"title": "Educação Financeira e Finanças: contribuições educacionais da OBInvest",
     "authors": "PASSOS, G. G. F. G.; SANTOS, W. D.; SILVA, L. Y. C.; RIBEIRO, S.; et al.",
     "venue": "Editora Akademy, 1. ed. São Paulo", "year": 2026,
     "tags": ["Educação Financeira", "OBInvest"], "kind": "book"},
    {"title": "Literature Review on the Theory of Constraints Applied in the Software Development Process",
     "authors": "RIBEIRO, S.; SCHMITZ, E.; ALENCAR, A.; SILVA, M.",
     "venue": "IEEE Latin America Transactions, v. 16, p. 2747–2756", "year": 2018,
     "tags": ["Engenharia de Software", "Otimização"], "kind": "article"},
]

SEED_NEWS = [
    {"title_pt": "MAF apresenta estudo de fatos estilizados FIIs × REITs no XXV Encontro Brasileiro de Finanças",
     "title_en": "MAF presents stylized-facts study of FIIs vs REITs at the XXV Brazilian Finance Meeting",
     "summary_pt": "O trabalho dos pesquisadores Gilberto Passos, Sildenir Ribeiro e Eber Schmitz aplica estatísticas de mercados artificiais para comparar fundos imobiliários brasileiros e REITs americanos.",
     "summary_en": "Research by Gilberto Passos, Sildenir Ribeiro and Eber Schmitz applies artificial-market statistics to compare Brazilian real estate funds with US REITs.",
     "date": "2025-07-14", "tag": "PUBLICAÇÃO", "featured": True, "image_url": IMG_ORDERBOOK},
    {"title_pt": "Simulação baseada em agentes do GeronTrack é publicada no WESAAC 2025",
     "title_en": "GeronTrack agent-based simulation published at WESAAC 2025",
     "summary_pt": "Estudo do Prof. Cristiano Fuschilo utiliza ABMS para monitoramento de indicadores em Instituições de Longa Permanência para Idosos.",
     "summary_en": "Study by Prof. Cristiano Fuschilo uses ABMS to monitor indicators in long-term care institutions for the elderly.",
     "date": "2025-05-30", "tag": "PUBLICAÇÃO", "featured": False, "image_url": IMG_MESH},
    {"title_pt": "OBInvest abre inscrições com trilha de mercado artificial",
     "title_en": "OBInvest opens registrations with an artificial-market track",
     "summary_pt": "A Olimpíada Brasileira de Investimentos, fundada pelo Prof. Gilberto Passos com apoio do CNPq, usará o simulador de mercado artificial do laboratório como ferramenta pedagógica.",
     "summary_en": "The Brazilian Investment Olympiad, founded by Prof. Gilberto Passos with CNPq support, will use the lab's artificial market simulator as a teaching tool.",
     "date": "2026-03-02", "tag": "OBINVEST", "featured": False, "image_url": IMG_RESEARCH},
    {"title_pt": "Laboratório inaugura micromercado artificial para estudo de crashes e liquidez",
     "title_en": "Lab launches artificial micromarket for crash and liquidity research",
     "summary_pt": "Nova infraestrutura de simulação multiagente replica book de ofertas, formação de preços e cascatas de pânico com milhares de agentes cognitivos autônomos.",
     "summary_en": "New multi-agent simulation infrastructure replicates order books, price formation and panic cascades with thousands of autonomous cognitive agents.",
     "date": "2026-06-20", "tag": "LAB", "featured": False, "image_url": IMG_NEURAL},
]

SEED_TEAM = [
    {"name": "Prof. Dr. Eber Assis Schmitz", "group": "ufrj", "order": 1,
     "role_pt": "Professor Associado · Coordenador do Laboratório", "role_en": "Associate Professor · Lab Coordinator",
     "institution": "UFRJ · Instituto de Matemática / PPGI",
     "areas_pt": ["Engenharia de Software", "Modelagem e Simulação", "Análise de Risco em TI", "Economia de Software", "Mercados Artificiais"],
     "areas_en": ["Software Engineering", "Modeling & Simulation", "IT Risk Analysis", "Software Economics", "Artificial Markets"],
     "education": ["Doutorado em Computing and Control — Imperial College London (1980)", "Mestrado em Engenharia Elétrica — UFRJ (1973)", "Graduação em Engenharia Eletrônica — UFRGS (1971)"],
     "bio_pt": "Doutor pelo Imperial College London e professor associado da UFRJ. Pesquisa modelagem e simulação de processos, análise de risco em projetos de TI e economia da engenharia de software. Orienta a pesquisa do Mercado Financeiro Artificial Brasileiro que dá origem ao MAF.",
     "bio_en": "Ph.D. from Imperial College London and associate professor at UFRJ. Researches process modeling and simulation, IT project risk analysis and software engineering economics. Supervises the Brazilian Artificial Financial Market research that gave rise to MAF.",
     "highlight_pt": "Coordenador do laboratório e orientador da tese do Mercado Financeiro Artificial Brasileiro.",
     "highlight_en": "Lab coordinator and supervisor of the Brazilian Artificial Financial Market thesis.",
     "lattes": "http://lattes.cnpq.br/0369165171803086", "orcid": "https://orcid.org/0000-0002-4839-4606"},
    {"name": "Prof. Dr. Sildenir Alves Ribeiro", "group": "cefet", "order": 2,
     "role_pt": "Professor · Bacharelado em Sistemas de Informação", "role_en": "Professor · B.Sc. Information Systems",
     "institution": "CEFET/RJ · Campus Maria da Graça",
     "areas_pt": ["Otimização", "Inteligência Computacional", "Engenharia de Software Experimental", "Ciência de Dados", "Governança de TI"],
     "areas_en": ["Optimization", "Computational Intelligence", "Experimental Software Engineering", "Data Science", "IT Governance"],
     "education": ["Pós-Doutorado em Informática — UFRJ (2018–2020)", "Doutorado em Informática — NCE/UFRJ (2018)", "Mestrado em Informática — UFES (2006)", "Graduação em Ciência da Computação — UNIC (2001)"],
     "bio_pt": "Doutor em Informática pela UFRJ com pós-doutorado no instituto Tércio Pacitti (NCE/UFRJ). Atua em otimização, inteligência computacional e engenharia de software experimental, com publicações na IEEE Latin America Transactions e Ciência & Saúde Coletiva.",
     "bio_en": "Ph.D. in Informatics from UFRJ with postdoctoral research at NCE/UFRJ. Works in optimization, computational intelligence and experimental software engineering, published in IEEE Latin America Transactions and Ciência & Saúde Coletiva.",
     "highlight_pt": "Pesquisador do grupo HumânITas e orientador de mestrado no PPGI/UFRJ.",
     "highlight_en": "HumânITas research group member and M.Sc. supervisor at PPGI/UFRJ.",
     "lattes": "http://lattes.cnpq.br/1300978002176747"},
    {"name": "Prof. Me. Gilberto Gil Passos", "group": "cefet", "order": 3,
     "role_pt": "Professor · Doutorando em Informática (PPGI/UFRJ)", "role_en": "Professor · Ph.D. Candidate in Informatics (PPGI/UFRJ)",
     "institution": "CEFET/RJ · Campus Maria da Graça",
     "areas_pt": ["Mercados Artificiais", "Modelagem Baseada em Agentes", "Educação Financeira", "Sistemas Complexos", "Matemática Aplicada"],
     "areas_en": ["Artificial Markets", "Agent-Based Modeling", "Financial Education", "Complex Systems", "Applied Mathematics"],
     "education": ["Doutorado em andamento em Informática — UFRJ (desde 2022)", "Especialização em Gestão Financeira — Mackenzie (2021)", "Mestrado Profissional em Matemática — UFRJ (2015)", "Graduação em Matemática — UERJ (2012)"],
     "bio_pt": "Fundador da OBInvest — Olimpíada Brasileira de Investimentos (2020), apoiada pelo CNPq, e membro do Fórum de Olimpíadas Científicas do MCTI. Sua tese desenvolve o Mercado Financeiro Artificial Brasileiro: ABM como ferramenta pedagógica para a OBInvest.",
     "bio_en": "Founder of OBInvest — Brazilian Investment Olympiad (2020), supported by CNPq, and member of the MCTI Scientific Olympiads Forum. His thesis builds the Brazilian Artificial Financial Market: ABM as a teaching tool for OBInvest.",
     "highlight_pt": "Tese: “Mercado Financeiro Artificial Brasileiro — o uso de ABM como ferramenta pedagógica para a OBInvest” (orientador: Prof. Eber Schmitz).",
     "highlight_en": "Thesis: “The Brazilian Artificial Financial Market — ABM as a pedagogical tool for OBInvest” (supervisor: Prof. Eber Schmitz).",
     "lattes": "http://lattes.cnpq.br/6595505865792633", "orcid": "https://orcid.org/0009-0007-5848-8298"},
    {"name": "Prof. Me. Cristiano Fuschilo", "group": "cefet", "order": 4,
     "role_pt": "Professor EBTT · Bacharelado em Sistemas de Informação", "role_en": "Professor · B.Sc. Information Systems",
     "institution": "CEFET/RJ · Campus Maria da Graça",
     "areas_pt": ["Simulação Baseada em Agentes", "Análise Envoltória de Dados (DEA)", "Seleção de Portfólios", "Assistentes Virtuais Inteligentes", "Robótica Educacional"],
     "areas_en": ["Agent-Based Simulation", "Data Envelopment Analysis (DEA)", "Portfolio Selection", "Intelligent Virtual Assistants", "Educational Robotics"],
     "education": ["Mestrado em Informática — UFRJ (2022)", "Especialização em Análise e Projeto de Sistemas — PUC-Rio (2003)", "Graduação em Processamento de Dados — PUC-Rio (1998)"],
     "bio_pt": "Mestre em Informática pela UFRJ, com dissertação sobre avaliação de assistentes virtuais inteligentes via Análise Envoltória de Dados (orientação: Prof. Eber Schmitz; coorientação: Prof. Sildenir Ribeiro). Experiência de mercado financeiro na Ágora Corretora, em projetos de venda on-line de fundos de investimento.",
     "bio_en": "M.Sc. in Informatics from UFRJ, with a dissertation on intelligent virtual assistant evaluation using Data Envelopment Analysis (advisor: Prof. Eber Schmitz; co-advisor: Prof. Sildenir Ribeiro). Financial-market industry experience at Ágora brokerage, on online mutual-fund sales projects.",
     "highlight_pt": "Publicou simulação baseada em agentes do GeronTrack no WESAAC 2025.",
     "highlight_en": "Published the GeronTrack agent-based simulation at WESAAC 2025.",
     "lattes": "http://lattes.cnpq.br/1214558945534442", "orcid": "http://orcid.org/0000-0003-2050-8074"},
    {"name": "Raphael M. Sanches de Jesus", "group": "ufrj", "order": 5,
     "role_pt": "Pesquisador · Mestrando em Informática (PPGI/UFRJ)", "role_en": "Researcher · M.Sc. Candidate in Informatics (PPGI/UFRJ)",
     "institution": "UFRJ / PPGI · Professor na Universidade Estácio de Sá",
     "areas_pt": ["Engenharia de Software", "Arquiteturas Escaláveis", "Microsserviços", "Simulação Computacional", "Desenvolvimento Full-Stack"],
     "areas_en": ["Software Engineering", "Scalable Architectures", "Microservices", "Computational Simulation", "Full-Stack Development"],
     "education": ["Mestrado em andamento em Informática — UFRJ (orientador: Prof. Sildenir Ribeiro)", "Especialização em Desenvolvimento Java — UNESA (2014)", "Graduação em Sistemas de Informação — UNESA (2011)"],
     "bio_pt": "Professor e pesquisador com mais de 20 anos de experiência em desenvolvimento de software, arquiteturas escaláveis e integração de APIs. Leciona programação (Java, Python, JavaScript, C++) e frameworks como React, FastAPI e Laravel.",
     "bio_en": "Professor and researcher with 20+ years of software development experience in scalable architectures and API integration. Teaches programming (Java, Python, JavaScript, C++) and frameworks such as React, FastAPI and Laravel.",
     "highlight_pt": "Desenvolve a infraestrutura computacional das simulações do laboratório.",
     "highlight_en": "Builds the computational infrastructure behind the lab's simulations.",
     "lattes": "http://lattes.cnpq.br/2882539440409307", "linkedin": "https://www.linkedin.com/in/raphael-mauricio/"},
    {"name": "Hugo Fraga", "group": "ufrj", "order": 6,
     "role_pt": "Pesquisador Discente · Mestrando (PPGI/UFRJ)", "role_en": "Graduate Researcher · M.Sc. Candidate (PPGI/UFRJ)",
     "institution": "UFRJ / PPGI",
     "areas_pt": ["Mundos Artificiais", "Modelagem Baseada em Agentes", "Finanças Computacionais"],
     "areas_en": ["Artificial Worlds", "Agent-Based Modeling", "Computational Finance"],
     "education": ["Mestrado em andamento em Informática — PPGI/UFRJ"],
     "bio_pt": "Pesquisador discente do laboratório, dedicado ao desenvolvimento de micromercados artificiais e agentes cognitivos para o estudo de dinâmicas financeiras emergentes.",
     "bio_en": "Graduate researcher at the lab, focused on building artificial micro-markets and cognitive agents to study emergent financial dynamics.",
     "highlight_pt": "Integrante mais jovem da equipe de simulação do MAF.",
     "highlight_en": "Youngest member of the MAF simulation team.",
     "lattes": None},
]


async def seed_content():
    if await db.publications.count_documents({}) == 0:
        await db.publications.insert_many([Publication(**p).model_dump() for p in SEED_PUBLICATIONS])
    if await db.news.count_documents({}) == 0:
        await db.news.insert_many([News(**n).model_dump() for n in SEED_NEWS])
    else:
        for n in SEED_NEWS:
            if n.get("image_url"):
                await db.news.update_many(
                    {"title_pt": n["title_pt"], "image_url": {"$in": [None, ""]}},
                    {"$set": {"image_url": n["image_url"]}},
                )
    if await db.team_members.count_documents({}) == 0:
        await db.team_members.insert_many([TeamMember(**m).model_dump() for m in SEED_TEAM])


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")
    await seed_admin()
    await seed_content()


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
