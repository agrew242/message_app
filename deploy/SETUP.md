# Setting up Messenger for you and your friends

By the end you'll have:

- **The relay** (the server that passes encrypted messages along) on a small rented server, at `https://relay.yourdomain.com`.
- **The app** at `https://chat.yourdomain.com`. GitHub Pages builds it from this repository's code and serves it, separately from the relay.
- **Messenger on your iPhone's Home Screen**, with notifications.

It costs about 10–15 USD a year for a domain plus 4–6 USD a month for the server. GitHub Pages is free for this public repository. Allow an hour or so the first time.

> Messenger hasn't had an outside security review yet. It's built to keep the server from reading anything, but until it's been reviewed, use Signal for anything truly sensitive.

## 1. Get a domain and a server

1. **Domain:** buy one from any registrar (Cloudflare, Porkbun, Namecheap, …). These steps use `yourdomain.com`.
2. **Server:** rent the smallest Linux server from any cloud provider (Hetzner, DigitalOcean, Vultr, …). Pick **Ubuntu** (24.04 or newer) and add your SSH key when asked. 1 GB of memory is plenty to run the relay.
3. Note the server's **IP address**.

## 2. Point two names at them (DNS)

At your registrar's DNS settings, add:

| Type | Name | Value |
| --- | --- | --- |
| A | `relay` | your server's IPv4 address |
| AAAA | `relay` | its IPv6 address, if it has one |
| CNAME | `chat` | `agrew242.github.io` |

DNS changes can take a few minutes to an hour to spread.

## 3. Start the relay on the server

Log in with `ssh root@<server IP>` (or the user your provider gave you), then:

```sh
# Docker
curl -fsSL https://get.docker.com | sh

# Some swap, so building the relay fits on a 1 GB server
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Firewall: SSH and web traffic only
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443 && ufw --force enable

# The code
git clone https://github.com/agrew242/message_app.git
cd message_app/deploy
cp .env.example .env
nano .env
```

In `.env`, set:

- `RELAY_DOMAIN=relay.yourdomain.com`
- `APP_ORIGIN=https://chat.yourdomain.com` (exactly that: `https://`, no path, no trailing slash)
- `CONTACT_EMAIL=` your email address. Let's Encrypt and the push services use it only to warn you about problems.

Save with Ctrl+O, Enter, Ctrl+X. Then start everything:

```sh
docker compose up -d --build     # the first build takes about 10 minutes
docker compose logs relay        # look for: First invite code (valid 7 days): xxxxx-xxxxx-xxxxx-xxxxx
curl https://relay.yourdomain.com/healthz   # should print: ok
```

**Keep that first invite code:** it's how you'll sign up. The relay prints a new one every time it starts until someone has used one. Caddy gets the HTTPS certificate on its own within a minute of starting. If `curl` complains about the certificate, wait a minute and try again.

## 4. Publish the app with GitHub Pages

In the repository on github.com:

1. **Settings → Pages → Build and deployment → Source:** choose **GitHub Actions**.
2. Same page, **Custom domain:** enter `chat.yourdomain.com` and save. When the DNS check passes, tick **Enforce HTTPS** (the certificate can take a few minutes).
3. **Settings → Secrets and variables → Actions → Variables → New repository variable:** name `RELAY_URL`, value `https://relay.yourdomain.com`.
4. **Actions → Publish the web app → Run workflow.** It also runs by itself whenever `main` changes.
5. Open `https://chat.yourdomain.com`. You should see "Welcome to Messenger".

<details>
<summary>No domain for the app? Use the github.io address instead</summary>

Skip the custom domain, add a second variable `BASE_HREF` = `/message_app/`, and the app lives at `https://agrew242.github.io/message_app/`. On the server, set `APP_ORIGIN=https://agrew242.github.io` in `.env` and run `docker compose up -d`. Any other GitHub Pages site under that same address would share the app's browser storage, so a domain of your own is better.

</details>

## 5. Join from your iPhone

1. Open `https://chat.yourdomain.com` in **Safari**.
2. Tap **Share**, then **Add to Home Screen**, then **Add**.
3. **Open Messenger from the Home Screen** (not from Safari) and sign up there with the first invite code. On iPhone, the Home Screen app and Safari keep separate storage. Your account and messages live in whichever one you sign up in, and only the Home Screen app can show notifications.
4. Tap your picture (top left) → **Notifications → Turn on**.
5. Same screen → **App PIN** (recommended). Without it, someone with your unlocked phone could read the app's files; with it, they're encrypted under your PIN.
6. **Invite friends:** in Chats, tap the add-person button. Each code works once, for 7 days, and the link pre-fills it. Send your friends this same guide's step 5.

## 6. Verify each other (once per friend)

When you're together: open your chat, tap their name at the top, then **Verify → Scan their code**, and have them scan yours. Or, on a call, read the 60-digit safety number to each other and tap **The numbers match**.

Once you've verified someone, the app refuses to add them to a chat if their key ever changes, until you check again. If a friend reinstalls, they'll show as changed; verify them again.

## Looking after it

- **Updates:** `cd ~/message_app && git pull && cd deploy && docker compose up -d --build`. The app itself updates when `main` changes.
- **Backups:** run `./deploy/backup.sh` daily from cron (`crontab -e`, then `15 3 * * * /root/message_app/deploy/backup.sh`). It keeps the last 14 copies in `deploy/backups/`.
  - The relay's database holds accounts, devices, who's in which chat, and mail not yet delivered. It has no message text.
  - If you lose it, everyone has to sign up again and start new chats.
  - Restoring an old backup brings accounts back, but chats changed since then may need to be started again.
- **Logs:** `docker compose logs -f relay`. They list routes and status codes only: no usernames, no chat ids, no message contents.
- **Disk:** tiny. Undelivered mail and photos are deleted after 30 days.

## Good to know

- **Messages live only on your phones.** If you delete the Home Screen app or clear its data, that phone's history is gone. Encrypted backups come in a later phase.
- **iPhone keeps Home Screen app data:** it doesn't apply Safari's 7-day cleanup of website data to apps on the Home Screen. That's another reason to use the app from there.
- **Notifications** only ever say "New message": the relay can't know more, and doesn't put anything in them.
- **Photos** are resized and their metadata (including location) is removed before they're encrypted and sent.
- **The relay can see** usernames, which devices share a chat, when messages are sent and roughly how big they are, and your IP address. It can't see what you send, your display names, or who's typing.
