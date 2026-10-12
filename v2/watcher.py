#!/usr/bin/env python3
"""
IITB internship-blog watcher -> Telegram pusher.

Flow:
  1. Poll Telegram for new /start (subscribe), /stop (unsubscribe), and
     /list (admin-only subscriber list) messages; update subscribers.json.
  2. Log in via requests.Session using username + password + live TOTP code.
  3. Fetch the blog/portal page.
  4. Parse post entries (title + link).
  5. Diff against seen.json; broadcast new entries to every subscriber.

TELEGRAM_CHAT_ID is your own (admin) chat — used for /list authorization
and for ops alerts (e.g. "SSO login failed"), NOT the broadcast list.
Anyone who DMs the bot /start gets added to the actual broadcast list in
subscribers.json.

Run manually:  python3 watcher.py
Run via cron:  see README.md
"""

import os
import sys
import re
import json
import time
import hashlib
import fcntl
import requests
import feedparser
from bs4 import BeautifulSoup
from pathlib import Path
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from dotenv import load_dotenv

from common import (
    HTTP_TIMEOUT,
    atomic_write_bytes,
    load_session,
    save_session,
    login,
    send_telegram as _telegram_send,
)

load_dotenv()

STATE_FILE = Path(__file__).parent / "seen.json"
SUBSCRIBERS_FILE = Path(__file__).parent / "subscribers.json"
OFFSET_FILE = Path(__file__).parent / "telegram_offset.json"
HISTORY_FILE = Path(__file__).parent / "history.json"
PENDING_FILE = Path(__file__).parent / "pending_deliveries.json"
LOCK_FILE = Path(__file__).parent / "watcher.lock"
LOGIN_BACKOFF_FILE = Path(__file__).parent / "login_backoff.json"
MAX_HISTORY = 30  # how many recent posts we keep around for /start catch-up

# A blog fetch returning zero posts isn't reliable evidence the SSO session
# actually expired — the site can serve its SPA shell instead of RSS for
# reasons unrelated to auth (e.g. currently down), and every 60s cycle would
# otherwise re-trigger a REAL SSO login (username+password+TOTP) against
# IITB's server. That's what caused "many SSO signings" against the old bot.
# This cooldown caps real login attempts to once per window regardless of
# how many consecutive cycles report zero posts.
LOGIN_RETRY_COOLDOWN = timedelta(minutes=15)

REQUIRED_ENV = [
    "SSO_LOGIN_URL", "SSO_USERNAME", "SSO_PASSWORD", "SSO_TOTP_SECRET",
    "BLOG_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
]


def check_env():
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        print(f"Missing env vars: {missing}. Copy .env.example to .env and fill it in.")
        sys.exit(1)


def fetch_posts(session: requests.Session, quiet: bool = False):
    """Fetch the blog's RSS feed and parse entries. RSS gives us clean
    structured title/link/content/date — no CSS selector guessing needed.

    The portal uses OAuth2/OIDC (mod_auth_openidc). The FIRST hit to a
    protected URL may trigger the full auth handshake and land you on the
    portal's SPA shell instead of the originally requested resource, because
    the callback doesn't preserve the original target. Once the session
    cookie is set though, a second direct request should serve real content.

    quiet=True suppresses debug output — used for the initial "try the
    reused session" probe in main(), where failure is expected/normal and
    just means we fall through to a fresh login.
    """
    base_url = os.getenv("BLOG_URL").rstrip("/")
    feed_url = f"{base_url}/?feed=rss2"

    def _try_fetch():
        resp = session.get(feed_url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        found = []
        for entry in feed.entries:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            guid = entry.get("id", link)
            published = entry.get("published", "")
            raw_content = ""
            if "content" in entry and entry["content"]:
                raw_content = entry["content"][0].get("value", "")
            elif "summary" in entry:
                raw_content = entry.get("summary", "")
            if title and link:
                found.append({
                    "title": title,
                    "link": link,
                    "guid": guid,
                    "published": published,
                    "raw_content": raw_content,
                })
        return resp, feed, found

    resp, feed, posts = _try_fetch()

    if not posts:
        if not quiet:
            print("First fetch returned no posts — retrying once (session may have just been established)...")
        resp, feed, posts = _try_fetch()

    if not posts and not quiet:
        print("--- DEBUG: no posts parsed after retry ---")
        print(f"Feed URL: {feed_url}")
        print(f"Status code: {resp.status_code}")
        print(f"feedparser bozo (parse error) flag: {feed.get('bozo')}")
        print(f"First 300 chars of raw response: {resp.text[:300]!r}")
        print(f"Current session cookies: {list(session.cookies.keys())}")
        print("-------------------------------")

    return posts


TABLE_MARK_START = "\u0000TBL\u0000"
TABLE_MARK_END = "\u0000/TBL\u0000"

# Matches the word "IEOR" (any case) or a roll number starting 24b45/24B45
# (e.g. 24b4525) so IEOR-relevant posts stand out in the Telegram message.
IEOR_HIGHLIGHT_RE = re.compile(r"\bIEOR\b|24[bB]45\d+")


def highlight_ieor(escaped_text: str) -> str:
    """Bold + underline IEOR mentions / 24b45-prefixed roll numbers so they
    stand out inline without the visual clutter of emoji boxes flanking
    the word. Must be called on text that is ALREADY HTML-escaped (the
    matches themselves are plain alphanumerics, so this is safe to run
    afterwards)."""
    return IEOR_HIGHLIGHT_RE.sub(lambda m: f"<b><u>{m.group(0)}</u></b>", escaped_text)


FIELD_LINE_RE = re.compile(r"^([A-Za-z][\w /&()\-]{1,28}):\s*(.+)$")


def format_paragraph_block(escaped_part: str) -> str:
    """Within one text block, tightly pack consecutive short 'Label: value'
    lines (Category: I1, Job Code: 2, CPI Cutoff: 8, ...) into a single
    bold-label bullet list, instead of leaving each one as its own
    paragraph with a blank line above and below — that spacing is what
    made the message feel sparse and disjointed. Longer/normal paragraphs
    are left alone. Expects text that's already HTML-escaped/highlighted."""
    paragraphs = [p for p in re.split(r"\n\s*\n", escaped_part) if p.strip()]
    out = []
    field_buf = []

    def flush():
        if field_buf:
            out.append("\n".join(field_buf))
            field_buf.clear()

    for para in paragraphs:
        para = para.strip()
        m = None if "\n" in para else FIELD_LINE_RE.match(para)
        if m and len(m.group(2)) <= 80:
            field_buf.append(f"▫️ <b>{m.group(1).strip()}:</b> {m.group(2).strip()}")
        else:
            flush()
            out.append(para)
    flush()
    return "\n\n".join(out)


def render_table(table) -> str:
    """Render a <table> as an aligned, monospace-friendly grid instead of
    a run-together '—'-joined line. Truncates long tables at a row boundary
    with a '+N more rows' note rather than cutting mid-row."""
    rows = []
    for row in table.find_all("tr"):
        cells = [c.get_text(strip=True) for c in row.find_all(["td", "th"])]
        if any(cells):
            rows.append(cells)
    if not rows:
        return ""

    ncols = max(len(r) for r in rows)
    rows = [r + [""] * (ncols - len(r)) for r in rows]

    MAX_ROWS = 40  # generous — a real cap only kicks in for genuinely huge tables
    extra = 0
    if len(rows) > MAX_ROWS:
        extra = len(rows) - MAX_ROWS
        rows = rows[:MAX_ROWS]

    widths = [max(len(r[i]) for r in rows) for i in range(ncols)]
    lines = [" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)).rstrip() for r in rows]

    out = "\n".join(lines)
    if extra:
        out += f"\n… +{extra} more rows (see full post)"
    return f"{TABLE_MARK_START}{out}{TABLE_MARK_END}"


def clean_content(html: str) -> str:
    """Strip HTML into readable text. Tables are pulled out and rendered as
    aligned monospace grids (marked with sentinels), everything else becomes
    plain text. Sentinels get turned into <pre> blocks in format_message.

    <br> tags get turned into a single space rather than a hard newline —
    a <br> is usually a line-wrap in the *middle* of one sentence (e.g.
    "Sign in with 1<br>or 2-page resume"), and treating it as a paragraph
    break was what made that sentence get chopped into separate lines.
    Only real block-level tags (p, div, li, headings) get an actual \\n.
    """
    soup = BeautifulSoup(html, "html.parser")

    for table in soup.find_all("table"):
        table.replace_with("\n" + render_table(table) + "\n")

    for br in soup.find_all("br"):
        br.replace_with(" ")

    BLOCK_TAGS = ["p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6"]
    for tag in soup.find_all(BLOCK_TAGS):
        tag.insert_before("\n")
        tag.insert_after("\n")

    text = soup.get_text(separator="")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def extract_deadline(text: str) -> str:
    """Pull out a 'Deadline: ...' line if present, for a highlighted callout."""
    match = re.search(r"Deadline\s*:?\s*([^\n]+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def render_for_telegram(text: str, budget: int) -> str:
    """Turn table-sentinel text into HTML, escaping plain text and wrapping
    table blocks in <pre>. Truncates on a whole-block boundary to fit
    `budget` chars rather than slicing mid-tag or mid-row."""
    parts = re.split(f"({TABLE_MARK_START}.*?{TABLE_MARK_END})", text, flags=re.DOTALL)

    rendered_blocks = []
    for part in parts:
        if part.startswith(TABLE_MARK_START):
            table_text = part[len(TABLE_MARK_START):-len(TABLE_MARK_END)]
            rendered_blocks.append(f"<pre>{escape_html(table_text)}</pre>")
        elif part.strip():
            escaped = highlight_ieor(escape_html(part.strip()))
            rendered_blocks.append(format_paragraph_block(escaped))

    out = []
    used = 0
    for block in rendered_blocks:
        if used + len(block) > budget:
            # Never slice rendered HTML: cutting inside a <pre>/<b> tag makes
            # Telegram reject the whole message. The post link in the footer
            # remains available when one unusually large block is omitted.
            out.append("…")
            break
        out.append(block)
        used += len(block)

    return "\n\n".join(out)


def load_json(path: Path, default):
    """A corrupt state file must not crash-loop the production daemon."""
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read {path.name}: {exc}; continuing with an empty state.")
        return default


def save_json(path: Path, data) -> None:
    atomic_write_bytes(path, json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))


def seconds_since_last_login_attempt() -> float | None:
    """None if we've never recorded an attempt (always allowed to login)."""
    data = load_json(LOGIN_BACKOFF_FILE, {})
    ts = data.get("last_attempt")
    if not ts:
        return None
    try:
        last = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - last).total_seconds()


def record_login_attempt() -> None:
    save_json(LOGIN_BACKOFF_FILE, {"last_attempt": datetime.now(timezone.utc).isoformat()})


def load_seen():
    return load_json(STATE_FILE, {})


def save_seen(seen):
    save_json(STATE_FILE, seen)


def load_history() -> list:
    """Most recent posts (newest first), kept so a brand-new subscriber
    can be sent a catch-up batch instead of starting from a blank slate."""
    return load_json(HISTORY_FILE, [])


def push_history(post: dict):
    history = load_history()
    history.insert(0, post)
    save_json(HISTORY_FILE, history[:MAX_HISTORY])


def post_id(post):
    key = post.get("guid") or post.get("link") or post.get("title")
    return hashlib.sha256(key.encode()).hexdigest()


# If the blog was unreachable for a while (an outage, or just not deployed
# yet) and comes back with a backlog of posts older than this, don't blast
# them all as fresh alerts — record them silently instead. Normal operation
# checks every 60s, so any genuinely new post is always well under this age.
STALE_POST_CUTOFF = timedelta(hours=48)


def post_age(post: dict):
    """Time since this post's RSS pubDate, or None if unparseable/missing
    (caller should treat that conservatively — i.e. still alert)."""
    raw = post.get("published")
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - dt


def escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_message(post: dict) -> str:
    raw_title = post["title"]
    # Keep pathological upstream values from making the header itself exceed
    # Telegram's 4096-character cap. Escaping happens after this limit.
    if len(raw_title) > 512:
        raw_title = raw_title[:511] + "…"
    link = post["link"]
    if len(link) > 512:
        link = link[:511] + "…"
    content = clean_content(post.get("raw_content", ""))
    deadline = extract_deadline(content)

    if deadline:
        # Remove the raw "Deadline: ..." line from the body since it's
        # already shown in the highlighted callout above.
        content = re.sub(r"(?im)^\s*Deadline\s*:?\s*.*$\n?", "", content).strip()
        content = re.sub(r"\n{3,}", "\n\n", content)

    is_ieor = bool(IEOR_HIGHLIGHT_RE.search(raw_title) or IEOR_HIGHLIGHT_RE.search(content))
    title = highlight_ieor(escape_html(raw_title))

    header = f"🆕 <b>{title}</b>"
    if is_ieor:
        header = "📌 IEOR\n" + header
    if deadline:
        header += f"\n⏰ <b>Deadline:</b> {escape_html(deadline)}"
    # A URL with query parameters contains '&'; it must be escaped in HTML
    # mode or Telegram can reject the entire broadcast as malformed entities.
    footer = f"\n🔗 {escape_html(link)}"

    # Telegram caps messages at 4096 chars. Reserve room for header/footer,
    # give the rest to content.
    budget = 4096 - len(header) - len(footer) - 20  # small safety margin
    rendered_content = render_for_telegram(content, budget) if content else ""

    parts = [header]
    if rendered_content:
        parts.append(rendered_content)
    parts.append(footer.strip())

    return "\n\n".join(parts)


def load_subscribers() -> dict:
    """chat_id (str) -> {"first_name", "username", "joined"}, for everyone
    who has /start'd the bot. This is the broadcast list for new posts."""
    return load_json(SUBSCRIBERS_FILE, {})


def save_subscribers(subs: dict):
    save_json(SUBSCRIBERS_FILE, subs)


def load_offset() -> int:
    """Telegram update_id to resume getUpdates from, so each cron run only
    sees messages sent since the last run instead of the whole history."""
    if OFFSET_FILE.exists():
        try:
            return int(json.loads(OFFSET_FILE.read_text(encoding="utf-8")).get("offset", 0))
        except (OSError, ValueError, json.JSONDecodeError):
            return 0
    return 0


def save_offset(offset: int):
    save_json(OFFSET_FILE, {"offset": offset})


def load_pending() -> dict:
    """Posts still owed to one or more subscribers after a transient error."""
    pending = load_json(PENDING_FILE, {})
    return pending if isinstance(pending, dict) else {}


def save_pending(pending: dict) -> None:
    save_json(PENDING_FILE, pending)


def acquire_process_lock():
    """Ensure only one Telegram long-poller owns this bot token at a time."""
    lock = open(LOCK_FILE, "a+")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        return None
    return lock


def _send_to_chat(chat_id: str, text: str) -> tuple:
    """Thin wrapper around common.send_telegram (which already handles
    flood-control retry) — kept as a local name since the rest of this
    file calls it with (chat_id, text) ordering throughout."""
    return _telegram_send(text, chat_id)


def poll_commands(subs: dict, long_poll_timeout: int = 0) -> dict:
    """Check for /start, /stop, /list messages sent to the bot since the
    last run and update the subscriber list accordingly. Returns the
    (possibly updated) subs dict — caller saves it.

    long_poll_timeout > 0 makes this a Telegram *long poll*: the request
    stays open server-side for up to that many seconds waiting for a new
    message, instead of returning immediately. That's what makes /start
    detection near-instant in run_forever() without busy-looping."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    admin_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    offset = load_offset()
    url = f"https://api.telegram.org/bot{token}/getUpdates"

    try:
        resp = requests.get(url, params={"offset": offset, "timeout": long_poll_timeout},
                             timeout=long_poll_timeout + 10)
        resp.raise_for_status()
        updates = resp.json().get("result", [])
    except Exception as e:
        print(f"getUpdates failed (skipping command polling this run): {e}")
        return subs

    for update in updates:
        # Persist the acknowledgement *before* replying. If the process is
        # restarted while a /list response is being sent, that command must
        # not be replayed indefinitely on the next start.
        update_id = update["update_id"]
        if update_id >= offset:
            offset = update_id + 1
            save_offset(offset)
        message = update.get("message") or update.get("edited_message")
        if not message:
            continue
        chat = message.get("chat", {})
        chat_id = str(chat.get("id"))
        text = (message.get("text") or "").strip()

        if text.startswith("/start"):
            is_new = chat_id not in subs
            subs[chat_id] = {
                "first_name": chat.get("first_name", ""),
                "username": chat.get("username", ""),
                "joined": subs.get(chat_id, {}).get("joined") or datetime.now(timezone.utc).isoformat(),
            }
            if is_new:
                _send_to_chat(chat_id,
                    "✅ Subscribed! I'll message you here whenever a new "
                    "internship/placement post shows up on the IITB blog.\n\n"
                    "Send /stop anytime to unsubscribe.")
                history = load_history()
                if history:
                    catchup = list(reversed(history[:10]))  # oldest-first, so the newest ends up last/most-recent
                    _send_to_chat(chat_id, f"📋 Catching you up on the last {len(catchup)} post(s)...")
                    for p in catchup:
                        _send_to_chat(chat_id, format_message(p))
                        time.sleep(0.3)

        elif text.startswith("/stop"):
            if chat_id in subs:
                del subs[chat_id]
                _send_to_chat(chat_id, "🛑 Unsubscribed — no further updates. Send /start to rejoin anytime.")

        elif text.startswith("/list"):
            if chat_id == admin_chat_id:
                if subs:
                    lines = []
                    for cid, info in subs.items():
                        name = info.get("first_name") or "Unknown"
                        uname = f" (@{info['username']})" if info.get("username") else ""
                        lines.append(f"• {name}{uname} — {cid}")
                    _send_to_chat(chat_id, f"👥 <b>{len(subs)} subscriber(s):</b>\n" + "\n".join(lines))
                else:
                    _send_to_chat(chat_id, "👥 No subscribers yet.")

    return subs


def discard_pending_telegram_updates() -> None:
    """Explicitly discard old queued bot commands during a deployment.

    Telegram's negative offset of -1 retains only the newest queued update and
    forgets all earlier ones. This is intentionally opt-in because it can drop
    real /start commands received while the bot was offline.
    """
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    try:
        response = requests.get(url, params={"offset": -1, "timeout": 0}, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        updates = response.json().get("result", [])
    except (requests.RequestException, ValueError) as exc:
        print(f"Could not discard pending Telegram updates: {exc}")
        sys.exit(1)

    if updates:
        save_offset(updates[-1]["update_id"] + 1)
        print("Discarded previously queued Telegram commands.")
    else:
        print("No queued Telegram commands to discard.")


def deliver_pending(pending: dict, subs: dict) -> tuple:
    """Deliver queued posts and retain transient failures for a later retry.

    New posts are recorded before delivery, so one flaky recipient can never
    cause all other subscribers to miss an alert. A recipient is removed only
    when Telegram explicitly says that the chat no longer exists or blocked us.
    """
    dead = set()
    for pid, entry in list(pending.items()):
        post = entry.get("post")
        remaining = entry.get("remaining", [])
        if not isinstance(post, dict) or not isinstance(remaining, list):
            print(f"Discarding malformed pending delivery {pid}.")
            pending.pop(pid, None)
            continue

        text = format_message(post)
        next_remaining = []
        for chat_id in remaining:
            chat_id = str(chat_id)
            if chat_id not in subs or chat_id in dead:
                continue  # the person unsubscribed, or was confirmed unreachable
            success, permanent_failure = _send_to_chat(chat_id, text)
            if success:
                pass
            elif permanent_failure:
                dead.add(chat_id)
            else:
                next_remaining.append(chat_id)
            time.sleep(0.05)  # stays safely below Telegram's global burst limit

        if next_remaining:
            entry["remaining"] = next_remaining
        else:
            pending.pop(pid, None)

    for chat_id in dead:
        print(f"Removing confirmed-unreachable subscriber {chat_id}")
        subs.pop(chat_id, None)
        for entry in pending.values():
            entry["remaining"] = [cid for cid in entry.get("remaining", []) if str(cid) != chat_id]
    return pending, subs


def check_and_broadcast(session: requests.Session, seen: dict, subs: dict, pending: dict) -> tuple:
    """Fetch the blog, diff against `seen`, and broadcast anything new to
    every subscriber. The feed lists newest post first — we send the new
    batch oldest-first so the actual newest post is the LAST one delivered
    (most recent message in each subscriber's chat), instead of arriving
    first and getting buried under an older post sent right after it.
    Also records each broadcast post in history.json for /start catch-up.

    Posts older than STALE_POST_CUTOFF are recorded into `seen` but never
    broadcast or added to history — this is what stops subscribers from
    getting blasted with a week of backlog the moment the blog recovers
    from being down.

    Returns (seen, subs, pending, ok) — ok is False only on an SSO login failure."""
    try:
        posts = fetch_posts(session, quiet=True)
    except requests.RequestException as exc:
        print(f"Blog fetch failed: {exc}")
        return seen, subs, pending, True

    if not posts:
        elapsed = seconds_since_last_login_attempt()
        if elapsed is not None and elapsed < LOGIN_RETRY_COOLDOWN.total_seconds():
            wait_left = int(LOGIN_RETRY_COOLDOWN.total_seconds() - elapsed)
            print(f"Blog check returned no posts; skipping re-login (cooldown active, {wait_left}s left) "
                  f"— zero posts isn't reliable proof the session is actually invalid.")
            return seen, subs, pending, True

        print("Saved session didn't work (expired or none saved) — logging in fresh...")
        record_login_attempt()
        if not login(session):
            # Login failures are an admin/ops concern, not a subscriber
            # broadcast — only alert the admin chat.
            _send_to_chat(os.getenv("TELEGRAM_CHAT_ID"),
                          "⚠️ Watcher: SSO login failed, check credentials/TOTP secret.")
            return seen, subs, pending, False
        try:
            posts = fetch_posts(session)
        except requests.RequestException as exc:
            print(f"Blog fetch after login failed: {exc}")
            return seen, subs, pending, True

    save_session(session)  # persist cookies for next run regardless

    if not posts:
        print("No posts parsed even after fresh login — check fetch_posts() debug output above.")
        return seen, subs, pending, True

    new_posts = [p for p in posts if post_id(p) not in seen]

    fresh_posts, stale_posts = [], []
    for p in new_posts:
        age = post_age(p)
        (stale_posts if age is not None and age > STALE_POST_CUTOFF else fresh_posts).append(p)

    for p in stale_posts:
        seen[post_id(p)] = p["title"]
    if stale_posts:
        print(f"Silently absorbed {len(stale_posts)} stale post(s) (older than {STALE_POST_CUTOFF}) without alerting.")

    for p in reversed(fresh_posts):
        pid = post_id(p)
        # setdefault keeps a partially delivered post intact across restarts.
        pending.setdefault(pid, {"post": p, "remaining": list(subs.keys())})
        seen[pid] = p["title"]
        push_history(p)

    pending, subs = deliver_pending(pending, subs)

    if fresh_posts:
        print(f"Broadcast {len(fresh_posts)} new post(s) to {len(subs)} subscriber(s).")
    else:
        print(f"Checked {len(posts)} posts, nothing new to broadcast.")

    return seen, subs, pending, True


def main():
    """Single pass: pick up any pending /start /stop, check the blog once,
    broadcast anything new, then exit. Meant for cron."""
    check_env()
    lock = acquire_process_lock()
    if not lock:
        print("Another watcher instance is already running; exiting.")
        return
    try:
        seen = load_seen()
        subs = load_subscribers()
        pending = load_pending()

        subs = poll_commands(subs)
        save_subscribers(subs)

        session = load_session()
        seen, subs, pending, ok = check_and_broadcast(session, seen, subs, pending)

        save_subscribers(subs)
        save_seen(seen)
        save_pending(pending)

        if not ok:
            sys.exit(1)
    finally:
        lock.close()


def run_forever(command_poll_interval: int = 5, rss_check_interval: int = 60):
    """Continuous local-testing mode: keeps a persistent process running
    so /start and /stop are picked up almost immediately (long-polling
    Telegram every `command_poll_interval` seconds) while the blog itself
    is only checked every `rss_check_interval` seconds, since it doesn't
    change nearly as often. Ctrl+C to stop.

    Note: this is a *polling* daemon meant for running locally (or on any
    machine that stays on) — it is NOT how you'd deploy this on Vercel or
    another serverless platform, since those don't keep a process running
    or keep local files (seen.json, subscribers.json, history.json)
    between invocations. A serverless deployment would swap this loop for
    a Telegram *webhook* (Telegram pushes /start instantly to your
    endpoint) plus a scheduled job (e.g. Vercel Cron) for the blog check,
    both backed by a real database instead of local JSON files."""
    check_env()
    lock = acquire_process_lock()
    if not lock:
        print("Another watcher instance is already running; exiting.")
        return
    seen = load_seen()
    subs = load_subscribers()
    pending = load_pending()
    session = load_session()
    last_rss_check = 0.0

    print(f"Running continuously (Ctrl+C to stop) — /start & /stop checked ~every "
          f"{command_poll_interval}s, blog checked every {rss_check_interval}s.")

    while True:
        try:
            subs = poll_commands(subs, long_poll_timeout=command_poll_interval)
            save_subscribers(subs)
        except Exception as e:
            print(f"poll_commands error (continuing): {e}")

        if time.time() - last_rss_check >= rss_check_interval:
            last_rss_check = time.time()
            try:
                seen, subs, pending, _ = check_and_broadcast(session, seen, subs, pending)
                save_seen(seen)
                save_subscribers(subs)
                save_pending(pending)
            except Exception as e:
                print(f"blog check error (continuing): {e}")


if __name__ == "__main__":
    if "--discard-pending-updates" in sys.argv:
        check_env()
        discard_pending_telegram_updates()
    elif "--daemon" in sys.argv:
        run_forever()
    else:
        main()
