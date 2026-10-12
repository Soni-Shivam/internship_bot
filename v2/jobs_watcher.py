#!/usr/bin/env python3
"""
internship_bot placements job-API monitor -> Telegram pusher.

This hits the SAME data the /applicant/jobs page shows, which appears
BEFORE the blog post gets written about it — so this is your early-warning
channel. Detects new IAFs, and flags walk-ins (confirmed real signal:
title contains "Walk-in"/"WALK-INS" AND the opensAt->closesAt window is
short, ~35 min in observed data).

Auth flow (different from the blog's mod_auth_openidc):
  1. Reuse the shared SSO session from common.py (logs in if needed).
  2. Hit sso.iitb.ac.in/authorize with the job-portal's client_id.
     Since SSO is already established, this completes without a fresh
     login and lands on campus.placements.iitb.ac.in/auth/student/login?code=...
  3. POST that code to /api/v1/auth/login/sso -> get a short-lived JWT
     (access_token), used as a Bearer token for the job API.
  4. Cache the token (with its own expiry) separately from the SSO
     session cookie, since it expires much sooner (~12h per the JWT
     `exp` claim seen in testing).

TELEGRAM_CHAT_ID is your own (admin) chat — used only for ops alerts (SSO
login failures, API errors). Job/IAF/deadline alerts broadcast to every
subscriber in subscribers.json instead, same list watcher.py maintains
via /start and /stop.

Run manually:  python3 jobs_watcher.py
Run via cron:  every 1-2 minutes if you want realistic walk-in coverage —
               a 30-minute sign-up window doesn't forgive a 15-minute cron.
"""

import os
import sys
import re
import json
import time
import base64
import hashlib
import secrets
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv

from common import (
    HTTP_TIMEOUT, atomic_write_bytes, load_session, save_session, login,
    send_telegram, load_subscribers, save_subscribers,
)

load_dotenv()

STATE_FILE = Path(__file__).parent / "jobs_seen.json"
TOKEN_FILE = Path(__file__).parent / "jobs_token.json"

SSO_AUTHORIZE_URL = "https://sso.iitb.ac.in/authorize"
JOB_CLIENT_ID = "placementserver-prod"
JOB_REDIRECT_URI = "https://campus.placements.iitb.ac.in/auth/student/login"
TOKEN_EXCHANGE_URL = "https://campus.placements.iitb.ac.in/api/v1/auth/login/sso"

REQUIRED_ENV = [
    "SSO_LOGIN_URL", "SSO_USERNAME", "SSO_PASSWORD", "SSO_TOTP_SECRET",
    "JOBS_API_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
]

WALKIN_TITLE_PATTERN = re.compile(r"(?i)walk[\s-]?in")
WALKIN_MAX_WINDOW = timedelta(minutes=45)  # confirmed real walk-ins run ~35 min
WALKIN_RECENT_OPEN_WINDOW = timedelta(hours=2)  # window-fallback only applies to jobs that just opened
DEADLINE_REMINDER_WINDOW = timedelta(hours=1)


def escape_html(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_ist(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        ist = dt.astimezone(timezone(timedelta(hours=5, minutes=30)))
        return ist.strftime("%d %b %Y, %I:%M %p IST")
    except Exception:
        return iso_str


def check_env():
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        print(f"Missing env vars: {missing}. Copy .env.example to .env and fill it in.")
        sys.exit(1)


def decode_jwt_exp(token: str):
    """Pull the `exp` claim out of a JWT without needing a JWT library —
    it's just base64url JSON in the middle segment."""
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return payload.get("exp")
    except Exception:
        return None


def load_cached_token():
    if not TOKEN_FILE.exists():
        return None
    try:
        data = json.loads(TOKEN_FILE.read_text())
        # Refresh a bit early (5 min buffer) rather than cutting it exactly at expiry
        if data.get("exp", 0) > time.time() + 300:
            return data.get("access_token")
    except Exception:
        pass
    return None


def save_token(access_token: str):
    exp = decode_jwt_exp(access_token) or (time.time() + 3600)
    atomic_write_bytes(
        TOKEN_FILE,
        json.dumps({"access_token": access_token, "exp": exp}).encode("utf-8"),
    )


def get_bearer_token(session: requests.Session):
    """Complete the SSO -> job-portal handoff to get a fresh Bearer token.
    Returns None if the SSO session itself isn't valid (caller should then
    call login() and retry)."""
    state = secrets.token_urlsafe(9)
    authorize_url = (
        f"{SSO_AUTHORIZE_URL}?response_type=code&client_id={JOB_CLIENT_ID}"
        f"&redirect_uri={requests.utils.quote(JOB_REDIRECT_URI, safe='')}"
        f"&state={state}&scope=openid"
    )

    try:
        resp = session.get(authorize_url, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        print(f"SSO authorization request failed: {exc}")
        return None
    parsed = urlparse(resp.url)
    qs = parse_qs(parsed.query)

    if "code" not in qs:
        return None  # SSO session not valid — caller falls back to login()

    auth_code = qs["code"][0]

    try:
        token_resp = session.post(
            TOKEN_EXCHANGE_URL,
            json={"authCode": auth_code, "role": "student"},
            headers={
                "content-type": "application/json",
                "accept": "application/json, text/plain, */*",
                "origin": "https://campus.placements.iitb.ac.in",
                "referer": resp.url,
            },
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        print(f"Token exchange request failed: {exc}")
        return None

    if token_resp.status_code not in (200, 201):
        print(f"Token exchange failed: {token_resp.status_code} {token_resp.text[:300]}")
        return None

    return token_resp.json().get("access_token")


def fetch_jobs(token: str):
    resp = requests.get(
        os.getenv("JOBS_API_URL"),
        headers={
            "accept": "application/json, text/plain, */*",
            "authorization": f"Bearer {token}",
        },
        timeout=HTTP_TIMEOUT,
    )
    if resp.status_code == 401:
        return None  # token expired/invalid — caller should refresh and retry
    resp.raise_for_status()
    return resp.json()


def is_walkin(job: dict) -> bool:
    """Confirmed from real data: walk-ins are titled '[Walk-in]'/'[WALK-INS]'
    AND have an opensAt->closesAt gap of ~35 minutes. Check both — title
    match alone in case formatting varies, window check as a safety net for
    an unlabeled short-notice slot.

    The window-only path is gated to jobs that opened recently. Confirmed
    false positive without this gate: a Google SDE listing posted 3 weeks
    ago with a coincidental 10-minute window, no "Walk-in" in the title —
    an old posting with a narrow window isn't a live walk-in signal, it's
    just administrative metadata."""
    if WALKIN_TITLE_PATTERN.search(job.get("title", "")):
        return True
    try:
        opens = datetime.fromisoformat(job["opensAt"].replace("Z", "+00:00"))
        closes = datetime.fromisoformat(job["closesAt"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - opens > WALKIN_RECENT_OPEN_WINDOW:
            return False
        if timedelta(0) < (closes - opens) <= WALKIN_MAX_WINDOW:
            return True
    except Exception:
        pass
    return False


def job_id(job: dict) -> str:
    return str(job.get("id"))


def job_title(job: dict) -> str:
    company = (job.get("company") or {}).get("name", "Unknown company")
    title = (job.get("title") or "").strip()
    return f"{company} — {title}" if title else company


def format_job_alert(job: dict, walkin: bool) -> str:
    title = escape_html(job_title(job))
    eligible = job.get("eligible")
    cpi = job.get("cpiCutoff")
    opens = to_ist(job.get("opensAt"))
    closes = to_ist(job.get("closesAt"))
    code = job.get("code")

    if walkin:
        header = "⚡ <b>WALK-IN DETECTED — before the blog!</b> ⚡\nQuick action needed — these windows close fast."
    else:
        header = "🚨 <b>IAF change detected — before the blog!</b>"

    if eligible is True:
        header += "\n✅ <b>You're eligible</b>"
    elif eligible is False:
        header += "\n🚫 Not eligible (per your CPI/branch)"

    lines = [header, "", f"<b>{title}</b>"]
    if code:
        lines.append(f"Job Code: {escape_html(code)}")
    if cpi:
        lines.append(f"CPI Cutoff: {cpi}")
    if opens:
        lines.append(f"Opens: {opens}")
    if closes:
        lines.append(f"Closes: {closes}")

    lines.append("")
    lines.append("🔗 https://campus.placements.iitb.ac.in/applicant/jobs")

    return "\n".join(lines)


def needs_deadline_reminder(job: dict, seen_entry: dict) -> bool:
    """True if this job's deadline is within the reminder window, hasn't
    already been reminded about, and you're actually eligible (no point
    reminding you to apply somewhere you can't)."""
    if seen_entry.get("reminded_deadline"):
        return False
    if job.get("eligible") is not True:
        return False
    try:
        closes = datetime.fromisoformat(job["closesAt"].replace("Z", "+00:00"))
    except Exception:
        return False
    now = datetime.now(timezone.utc)
    return timedelta(0) < (closes - now) <= DEADLINE_REMINDER_WINDOW


def format_deadline_reminder(job: dict) -> str:
    title = escape_html(job_title(job))
    closes = to_ist(job.get("closesAt"))
    code = job.get("code")

    lines = [
        "⏰ <b>1 HOUR LEFT to sign the IAF!</b> ⏰",
        "",
        f"<b>{title}</b>",
    ]
    if code:
        lines.append(f"Job Code: {escape_html(code)}")
    lines.append(f"Closes: {closes}")
    lines.append("")
    lines.append("🔗 https://campus.placements.iitb.ac.in/applicant/jobs")

    return "\n".join(lines)


def broadcast(text: str, subs: dict, dead: set) -> bool:
    """Send text to every subscriber not already known-dead this run.
    Chat_ids Telegram confirms are permanently unreachable (blocked/deleted)
    go into `dead` for the caller to prune from subs. Returns True if
    delivery to at least one subscriber failed transiently (caller should
    retry the whole message on the next run)."""
    any_failed = False
    for chat_id in list(subs.keys()):
        if chat_id in dead:
            continue
        delivered, permanent_failure = send_telegram(text, chat_id)
        if not delivered:
            if permanent_failure:
                dead.add(chat_id)
            else:
                any_failed = True
        time.sleep(0.05)  # stays safely below Telegram's global burst limit
    return any_failed


def load_seen():
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read {STATE_FILE.name}: {exc}; starting with an empty state.")
        return {}
    # Migrate old format ({id: "title string"}) to new dict-per-job format
    migrated = {}
    for jid, entry in data.items():
        if isinstance(entry, str):
            migrated[jid] = {"title": entry, "reminded_deadline": False}
        else:
            migrated[jid] = entry
    return migrated


def save_seen(seen):
    atomic_write_bytes(STATE_FILE, json.dumps(seen, indent=2, ensure_ascii=False).encode("utf-8"))


def main():
    check_env()
    is_first_run = not STATE_FILE.exists()
    seen = load_seen()
    session = load_session()

    token = load_cached_token()

    if not token:
        token = get_bearer_token(session)
        if not token:
            print("SSO session not valid — logging in fresh...")
            if not login(session):
                send_telegram("⚠️ Jobs watcher: SSO login failed, check credentials/TOTP secret.")
                sys.exit(1)
            save_session(session)
            token = get_bearer_token(session)
        if token:
            save_token(token)

    if not token:
        send_telegram("⚠️ Jobs watcher: could not obtain a job-API token after login.")
        sys.exit(1)

    try:
        data = fetch_jobs(token)
    except requests.RequestException as exc:
        print(f"Jobs API request failed: {exc}")
        send_telegram("⚠️ Jobs watcher: jobs API request failed; will retry on the next scheduled run.")
        sys.exit(1)

    if data is None:
        # Token expired between cache-check and use — refresh once and retry
        print("Token rejected by API — refreshing and retrying once...")
        token = get_bearer_token(session)
        if token:
            save_token(token)
            try:
                data = fetch_jobs(token)
            except requests.RequestException as exc:
                print(f"Jobs API retry failed: {exc}")
                data = None

    if data is None:
        send_telegram("⚠️ Jobs watcher: job API call failed even after token refresh.")
        sys.exit(1)

    # Confirmed from real response: bare list of job objects.
    jobs = data if isinstance(data, list) else data.get("jobs") or data.get("data") or []

    if not jobs:
        print("No jobs parsed — check the real response shape (see comment above fetch_jobs usage in main()).")
        print(f"Raw response (first 500 chars): {json.dumps(data)[:500]}")
        return

    new_jobs = [j for j in jobs if job_id(j) not in seen]

    if is_first_run:
        # The season's full job list (50+ entries, many already closed) would
        # otherwise blast as "new" on the very first run. Baseline silently.
        print(f"First run — baselining {len(new_jobs)} existing jobs silently (no alerts sent).")
        for j in new_jobs:
            seen[job_id(j)] = {"title": job_title(j), "reminded_deadline": False}
        save_seen(seen)
        return

    only_eligible = os.getenv("ONLY_ALERT_ELIGIBLE", "true").lower() == "true"
    alertable_new = new_jobs
    if only_eligible:
        skipped = [j for j in alertable_new if j.get("eligible") is False]
        alertable_new = [j for j in alertable_new if j.get("eligible") is not False]
        if skipped:
            print(f"Skipped {len(skipped)} new job(s) you're not eligible for (set ONLY_ALERT_ELIGIBLE=false in .env to see these too).")

    subs = load_subscribers()
    dead = set()

    failed_alert_ids = set()
    for j in alertable_new:
        walkin = is_walkin(j)
        if broadcast(format_job_alert(j, walkin), subs, dead):
            # Do not mark this job as seen. The next timer run will retry it,
            # rather than silently losing an alert during a Telegram outage.
            failed_alert_ids.add(job_id(j))
            print(f"Alert for job {job_id(j)} had a delivery failure; retaining it for retry.")

    # Register all newly-seen jobs (including skipped-ineligible ones) so
    # they don't get re-evaluated as "new" every run.
    for j in new_jobs:
        if job_id(j) in failed_alert_ids:
            continue
        seen[job_id(j)] = {"title": job_title(j), "reminded_deadline": False}

    # Deadline-reminder pass — checked against EVERY currently-listed job,
    # not just new ones, since a job that opened days ago can still be
    # approaching its deadline now.
    reminders_sent = 0
    for j in jobs:
        jid = job_id(j)
        if jid in failed_alert_ids:
            continue
        entry = seen.get(jid, {"title": job_title(j), "reminded_deadline": False})
        if needs_deadline_reminder(j, entry):
            if not broadcast(format_deadline_reminder(j), subs, dead):
                entry["reminded_deadline"] = True
                reminders_sent += 1
            else:
                print(f"Deadline reminder for job {jid} had a delivery failure; retaining it for retry.")
        seen[jid] = entry

    if dead:
        for chat_id in dead:
            print(f"Removing confirmed-unreachable subscriber {chat_id}")
            subs.pop(chat_id, None)
        save_subscribers(subs)

    save_seen(seen)
    print(f"Checked {len(jobs)} jobs, {len(alertable_new)} new alerts, {reminders_sent} deadline reminders, broadcast to {len(subs)} subscriber(s).")
    if failed_alert_ids:
        sys.exit(1)


if __name__ == "__main__":
    main()
