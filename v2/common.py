"""Shared SSO login, session persistence, and Telegram helpers used by both
watcher.py (blog) and jobs_watcher.py (job API)."""

import os
import re
import json
import time
import pickle
import tempfile
from html import unescape
from pathlib import Path

import requests
import pyotp
from dotenv import load_dotenv

load_dotenv()

SESSION_FILE = Path(__file__).parent / "session.pkl"
SUBSCRIBERS_FILE = Path(__file__).parent / "subscribers.json"
HTTP_TIMEOUT = (5, 30)  # connect, read; prevents a dead upstream from freezing a daemon


def load_subscribers() -> dict:
    """chat_id (str) -> {"first_name", "username", "joined"}, for everyone
    who has /start'd the bot. Shared broadcast list between watcher.py
    (blog posts) and jobs_watcher.py (job/IAF alerts)."""
    if not SUBSCRIBERS_FILE.exists():
        return {}
    try:
        return json.loads(SUBSCRIBERS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read {SUBSCRIBERS_FILE.name}: {exc}; continuing with an empty state.")
        return {}


def save_subscribers(subs: dict) -> None:
    atomic_write_bytes(SUBSCRIBERS_FILE, json.dumps(subs, indent=2, ensure_ascii=False).encode("utf-8"))


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Durably replace a state file without ever exposing a partial write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as tmp:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_name = tmp.name
    os.replace(temp_name, path)


def strip_telegram_html(text: str) -> str:
    """Convert a failed HTML message into safe plain text for a fallback send."""
    return unescape(re.sub(r"<[^>]+>", "", text))


def load_session() -> requests.Session:
    """Reuse a saved session (cookies) from a previous run if one exists,
    instead of logging in fresh every time."""
    session = requests.Session()
    if SESSION_FILE.exists():
        try:
            with open(SESSION_FILE, "rb") as f:
                session.cookies.update(pickle.load(f))
        except Exception:
            pass  # corrupt/old file — just start fresh, harmless
    return session


def save_session(session: requests.Session):
    atomic_write_bytes(SESSION_FILE, pickle.dumps(session.cookies))


def login(session: requests.Session) -> bool:
    """GET the login page first (to receive session cookies), then POST
    credentials + live TOTP code as x-www-form-urlencoded, matching the
    XHR the real site's JS makes. Once this succeeds, the session cookie
    is valid across ALL client_ids on sso.iitb.ac.in (blog + job API +
    anything else), since it's one identity provider — true SSO."""
    login_url = os.getenv("SSO_LOGIN_URL")

    try:
        session.get(login_url, timeout=HTTP_TIMEOUT)  # receive pre-auth cookies
    except requests.RequestException as exc:
        print(f"Login page request failed: {exc}")
        return False

    totp = pyotp.TOTP(os.getenv("SSO_TOTP_SECRET"))
    code = totp.now()

    payload = {
        "username": os.getenv("SSO_USERNAME"),
        "password": os.getenv("SSO_PASSWORD"),
        "totp": code,
        "redir": "/",
    }

    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "x-requested-with": "XMLHttpRequest",
        "origin": login_url.rsplit("/login", 1)[0],
        "referer": login_url,
    }

    try:
        resp = session.post(login_url, data=payload, headers=headers, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        print(f"Login request failed: {exc}")
        return False

    if resp.status_code != 200:
        print(f"Login failed. Status: {resp.status_code}, body: {resp.text[:300]}")
        return False

    try:
        data = resp.json()
        if data.get("error") or data.get("success") is False:
            print(f"Login rejected by server: {data}")
            return False
    except ValueError:
        pass  # not JSON, fall through — status 200 assumed success

    return True


def send_telegram(text: str, chat_id: str = None) -> tuple:
    """Send a message to a single Telegram chat. Defaults to the admin
    chat (TELEGRAM_CHAT_ID) if chat_id isn't given — this keeps existing
    single-chat callers (e.g. jobs_watcher.py) working unchanged.

    Returns (success, permanent_failure). permanent_failure is True only
    for errors meaning this chat_id will never work again (bot blocked,
    chat deleted) — safe to prune from a subscriber list. Transient errors
    (network blip, rate limit) are NOT permanent, so a subscriber isn't
    dropped for a momentary hiccup.

    Telegram flood-controls bursts of sendMessage calls with a 429 and a
    retry_after value — this waits it out and retries. A malformed HTML
    payload falls back to plain text instead of incorrectly deleting every
    otherwise-valid subscriber with a generic HTTP 400."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    for attempt in range(3):
        try:
            r = requests.post(url, data=payload, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            print(f"Telegram send to {chat_id} failed (attempt {attempt + 1}/3): {exc}")
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            return False, False

        if r.ok:
            return True, False

        body = r.text
        body_lower = body.lower()
        if r.status_code == 429:
            try:
                retry_after = float(r.json().get("parameters", {}).get("retry_after", 1))
            except (ValueError, TypeError):
                retry_after = 1
            print(f"Rate-limited sending to {chat_id}; waiting {retry_after}s before retrying.")
            time.sleep(min(retry_after + 0.5, 60))
            continue

        # Telegram uses 400 for both truly missing chats and message formatting
        # mistakes. Only remove an address when its error text proves it is gone.
        permanent = any(marker in body_lower for marker in (
            "bot was blocked by the user", "user is deactivated", "chat not found",
            "chat_id is empty",
        ))
        if permanent:
            print(f"Telegram recipient {chat_id} is unreachable: {r.status_code} {body}")
            return False, True

        if ("can't parse entities" in body_lower or "message is too long" in body_lower) and "parse_mode" in payload:
            print(f"Telegram rejected HTML for {chat_id}; retrying as plain text.")
            payload = {
                "chat_id": chat_id,
                "text": strip_telegram_html(text)[:4096],
                "disable_web_page_preview": True,
            }
            continue

        print(f"Telegram send to {chat_id} failed: {r.status_code} {body}")
        if r.status_code >= 500 and attempt < 2:
            time.sleep(2 ** attempt)
            continue
        return False, False

    return False, False
