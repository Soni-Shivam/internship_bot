# internship_bot

Telegram bot that watches IIT Bombay's internship/placement sources and pushes
new posts and job openings to subscribers.

It logs in through IITB SSO (username + password + TOTP) and runs two watchers:

| Script | How it runs | What it does |
|---|---|---|
| `v2/watcher.py` | long-running daemon (`--daemon`) | Polls the internship blog's RSS feed every ~60s and broadcasts new posts. Also handles Telegram commands: `/start` (subscribe + catch-up on recent posts), `/stop` (unsubscribe), `/list` (admin only). |
| `v2/jobs_watcher.py` | one-shot, every minute via systemd timer | Polls the placement portal job API (which updates *before* the blog), alerts on new IAFs, flags walk-ins, and sends deadline reminders. |
| `v2/common.py` | shared | SSO login, session persistence, subscriber list, Telegram sending with retry/rate-limit handling. |

`TELEGRAM_CHAT_ID` is your own admin chat (ops alerts + `/list`). The broadcast
list is everyone who has sent `/start`, stored in `v2/subscribers.json`.

## Requirements

- Python 3.10+
- An IITB SSO account with TOTP enabled, plus the **base32 TOTP seed** (not the 6-digit code)
- A Telegram bot token from [@BotFather](https://t.me/BotFather) and your chat id

## Local setup

```bash
git clone https://github.com/Soni-Shivam/internship_bot.git
cd internship_bot
python3 -m venv venv
./venv/bin/pip install -r requirements.txt

cp v2/.env.example v2/.env
chmod 600 v2/.env
$EDITOR v2/.env          # fill in every value
```

Run each watcher once to verify credentials and create the initial state:

```bash
cd v2
../venv/bin/python watcher.py        # single pass: SSO login + blog check
../venv/bin/python jobs_watcher.py   # single pass: token exchange + job API
```

The first `jobs_watcher.py` run silently records existing jobs in
`jobs_seen.json` as a baseline; only jobs that appear afterwards trigger alerts.

To run the blog bot continuously in the foreground:

```bash
../venv/bin/python watcher.py --daemon
```

## Deploying on a VM (systemd)

This is how it runs in production on a GCE `e2-micro` (Ubuntu). Any Linux box
with systemd works.

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip git

APP=$HOME/internship_bot
git clone https://github.com/Soni-Shivam/internship_bot.git "$APP"
cd "$APP"
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cp v2/.env.example v2/.env && chmod 700 v2 && chmod 600 v2/.env
nano v2/.env
```

Do the one-off test runs from *Local setup* above, then install the units.
The templates in `deploy/` use `YOUR_LINUX_USERNAME` and `YOUR_APP_PATH`
placeholders:

```bash
for unit in internship_bot-blog.service internship_bot-jobs.service internship_bot-jobs.timer; do
  sed -e "s|YOUR_LINUX_USERNAME|$USER|g" -e "s|YOUR_APP_PATH|$APP|g" "deploy/$unit" \
    | sudo tee "/etc/systemd/system/$unit" > /dev/null
done
sudo systemctl daemon-reload
sudo systemctl enable --now internship_bot-blog.service internship_bot-jobs.timer
```

Verify:

```bash
sudo systemctl status internship_bot-blog.service internship_bot-jobs.timer
sudo systemctl list-timers internship_bot-jobs.timer
```

Then send `/start` to the bot from a test account and `/list` from the admin chat.

> Only one instance may poll a given bot token. Stop any other copy of the bot
> (local or on another server) before starting a new deployment.

## Operations

```bash
# Logs
sudo journalctl -fu internship_bot-blog.service
sudo journalctl -fu internship_bot-jobs.service

# After changing code or v2/.env
git pull
sudo systemctl restart internship_bot-blog.service internship_bot-jobs.timer

# Drop Telegram commands queued while the bot was offline
# (e.g. a redeploy replaying old /list commands)
sudo systemctl stop internship_bot-blog.service
./venv/bin/python v2/watcher.py --discard-pending-updates
sudo systemctl start internship_bot-blog.service
```

## Runtime state

Everything below lives in `v2/`, is created automatically, and is gitignored.
Never commit it: several files contain credentials or subscriber data.

| File | Purpose | Safe to delete? |
|---|---|---|
| `.env` | credentials and config | no |
| `session.pkl` | SSO session cookies | yes, re-login on next run |
| `jobs_token.json` | cached placement-portal JWT | yes, regenerated |
| `subscribers.json` | broadcast list | no, subscribers are lost |
| `seen.json`, `jobs_seen.json` | already-alerted posts/jobs | no, everything re-alerts |
| `history.json` | recent posts for `/start` catch-up | yes, catch-up is empty until new posts arrive |
| `pending_deliveries.json` | Telegram retry queue | no, check the journal instead |
| `telegram_offset.json` | last processed Telegram update | yes, but old commands may replay |
| `login_backoff.json` | 15-minute cooldown between real SSO logins | yes |

When moving servers, copy `subscribers.json`, `seen.json`, `jobs_seen.json`
and `history.json` along with the code to keep subscribers and avoid duplicate
alerts.
