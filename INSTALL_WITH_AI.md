# CISO Brief: AI-assisted install

**For the human:** give this whole file to Claude, ChatGPT or another AI assistant and say:

> *"Follow INSTALL_WITH_AI.md and help me install CISO Brief."*

An assistant that can run commands on your computer (Claude Code, Claude desktop with a folder connected, ChatGPT with a terminal, Cursor, Copilot agent mode) will do most of the work itself. An assistant in a plain chat window will give you one command at a time to paste into your terminal and ask you to paste back what it prints. Either way, you'll be asked a few questions and will be up and running in 15 to 30 minutes.

---

## Instructions for the AI assistant

You are helping a person install **CISO Brief**, a free, self-hosted threat-intel emailer. It runs as a Docker Compose stack (Django web app, Celery worker and beat, Postgres, Redis, nginx, Mailpit, and optional Ollama). The website is only for configuring and previewing; the product is the email.

Your job is to get it running on their machine, sign them in, get their first brief into their inbox, and optionally turn on free API keys and real email delivery. Work through the phases in order. **Verify each phase before moving on.**

### Ground rules

1. **One step at a time.** If you can run commands, run them and read the output yourself. If you can't, give the user exactly one command (or one small group of related commands) and wait for them to paste the output. Never assume a step worked.
2. **Ask before deciding for them.** In particular: the AI option, the email option, and anything that deletes data.
3. **Secrets stay in `.env`.**
   - Ask the user to paste API keys and passwords **directly into `.env` in their editor**, not into this chat.
   - If they paste a key into the chat anyway, use it only to write it into `.env` (when you have file access), never repeat it back, and suggest they rotate it later if the chat is shared or logged.
   - Never commit `.env`, print its contents, or include keys in commands they might share.
4. **Never run `docker compose down -v`** (it deletes the database) without explaining that it erases all data and getting a clear yes. On a brand-new install with no data it's harmless, so say so.
5. **Don't change the application code** to get past an error. Use the troubleshooting table, re-check `.env`, and ask the user. If something is truly broken, help them file an issue.
6. **Detect the OS first** and use matching commands. Windows users should use PowerShell (or a WSL terminal); the commands below note where PowerShell differs.
7. Keep explanations short and plain. The user may be a security leader rather than an engineer.

---

### Phase 0: Ask three quick questions

Ask these together, with the recommended answer first:

1. **Which operating system?** Windows, macOS or Linux.
2. **Do you want AI-written briefs?**
   - **(a) Gemini free tier** (recommended for most): free, needs a Google account, prompts go to Google.
   - **(b) Local Ollama:** free and private, needs ~8 GB RAM and ~5 GB disk, and is slow without a GPU.
   - **(c) Off for now:** can be added later.
   - **(d) OpenAI:** paid, about $0.003 per brief.
3. **Where should emails go?**
   - **(a) Mailpit for now** (recommended to start): a local test inbox; nothing leaves the machine.
   - **(b) Real delivery via Gmail** (needs an App Password) **or another SMTP relay**: can be added later.

Record the answers and use them in phases 5 and 6.

### Phase 1: Prerequisites

Check:

```bash
docker --version
docker compose version
git --version
```

- If Docker is missing, send them to https://docs.docker.com/get-started/get-docker/. On Windows, Docker Desktop with the **WSL 2** backend. Have them start Docker Desktop and wait until it says it's running, then re-check.
- `docker compose version` must work. The old `docker-compose` (with a hyphen) is not enough.
- If Git is missing, they can download the ZIP from the GitHub page and unzip it instead.
- Check that ports 80 and 8025 are free:
  - macOS / Linux: `lsof -i :80 -i :8025`. No output means free.
  - Windows PowerShell: `Get-NetTCPConnection -LocalPort 80,8025 -State Listen -ErrorAction SilentlyContinue`. No output means free.
  - If a port is taken, use a different host port later (see troubleshooting).

**Pass when:** both Docker commands print versions and Docker is running (`docker ps` works without an error).

### Phase 2: Download

```bash
git clone https://github.com/eineEule/CISOBrief.git
cd CISOBrief
```

Every later command runs from this folder.

**Pass when:** listing the folder shows `docker-compose.yml`, `.env.example`, `backend/`, `infrastructure/` and `README.md`.

### Phase 3: Create `.env`

```bash
cp .env.example .env                 # PowerShell: Copy-Item .env.example .env
```

Generate a secret key:

```bash
docker run --rm python:3.12-alpine python -c "import secrets; print(secrets.token_urlsafe(50))"
```

Have the user open `.env` in a text editor (Notepad, TextEdit or VS Code) and set:

- `DJANGO_SECRET_KEY=` followed by the generated string
- `POSTGRES_PASSWORD=` followed by any long password (they won't need to type it again)

Leave everything else as is for now. If you have file access, you may write these two values yourself, since they're freshly generated and not the user's existing secrets.

**Pass when:** both lines in `.env` have non-placeholder values (not `change-me`), with no quotes and no spaces around `=`.

### Phase 4: Start the stack

```bash
docker compose up -d --build
```

The first build takes 3 to 10 minutes. Then:

```bash
docker compose ps
```

**Pass when:** `db`, `redis`, `web`, `worker`, `beat`, `nginx` and `mailpit` are all `running` (or `healthy`). If `web` keeps restarting, run `docker compose logs --tail=80 web` and use the troubleshooting table. Then confirm the site answers:

```bash
curl -sI http://localhost | head -1        # PowerShell: (Invoke-WebRequest http://localhost -UseBasicParsing).StatusCode
```

You should see `200` or `302`. If you can't run commands, have the user open http://localhost in a browser and confirm they see a sign-in page.

### Phase 5: Account and first brief

1. Have the user open **http://localhost/accounts/signup/** and fill in email, password, organization name, company domain (for example `acme.com`) and industry.
2. Have them open **http://localhost:8025** (Mailpit), open the confirmation email, and click the link. If no email arrived after a minute, check the worker: `docker compose logs --tail=50 worker`. As a fallback, mark the address verified (replace the email):
   ```bash
   docker compose exec web python manage.py shell -c "from allauth.account.models import EmailAddress as E; print(E.objects.filter(email__iexact='you@example.com').update(verified=True, primary=True))"
   ```
   It should print `1`.
3. Have them sign in at http://localhost. Their organization already has a starter mailer.
4. **Recommended:** load the demo company so they can see a full brief straight away (replace the email with the one they signed up with):
   ```bash
   docker compose exec web python manage.py seed_demo --now --email you@example.com
   ```
   This collects live data and builds two briefs: a Monday Board Brief and a Daily SOC Digest. It takes a few minutes.
5. Have them open **Mailers**, open a mailer, and look at the live preview on the right. Explain the builder briefly: audience → technology → early-warning watchlist (their domains and key suppliers) → modules → delivery.
6. Have them click **Send now** on the mailer list, then check Mailpit for the email.

**Pass when:** the user can see a brief email in Mailpit.

### Phase 6: Optional upgrades (follow the Phase 0 answers)

After any `.env` change, apply it with `docker compose up -d`. Changing `.env` does not need `--build`.

#### 6a. AI

| Choice | What the user does | Lines in `.env` |
|---|---|---|
| Gemini free tier | Go to https://aistudio.google.com/app/apikey, sign in with Google, click **Create API key**, and copy it | `AI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/`<br>`AI_API_KEY=<their key>`<br>Optionally `AI_MODEL=` a current Flash or Flash-Lite model listed in AI Studio |
| Local Ollama | Nothing to sign up for | `AI_BASE_URL=http://ollama:11434/v1`<br>On CPU only: `AI_TIMEOUT=600` and `AI_MODEL=qwen2.5:3b`<br>Then run `docker compose --profile local-ai up -d` (the first start downloads the model, ~5 GB) |
| OpenAI | Go to https://platform.openai.com/api-keys and create a key (needs billing) | `AI_API_KEY=sk-...` (leave `AI_BASE_URL` blank) |

Make sure each setting appears **once** in `.env`: edit the existing blank line rather than adding a duplicate. Then verify:

```bash
docker compose exec web python manage.py check_ai --quick
```

**Pass when:** the output contains `1/2 Connection and model work`. Then have the user click **Run AI preview** in the mailer builder.

#### 6b. Free threat-intel keys

Each key is optional and turns on one more early-warning source. Ask which they want; all three take about 2 minutes each.

| Source | Where | `.env` line |
|---|---|---|
| AlienVault OTX (community threat reports) | https://otx.alienvault.com: sign up → **Settings** → copy the **OTX Key** | `OTX_API_KEY=` |
| abuse.ch URLhaus (malware on your or a supplier's domain) | https://auth.abuse.ch/: sign in (GitHub, Google, X or LinkedIn) → **Save profile** → under **Optional**, generate an **Auth-Key** | `ABUSECH_AUTH_KEY=` |
| NVD (faster vendor CVE checks) | https://nvd.nist.gov/developers/request-an-api-key: submit the form, then click the activation link in the email within 7 days | `NVD_API_KEY=` |

Apply with `docker compose up -d`. These sources run on a schedule (every 6 to 24 hours); saving a mailer triggers an immediate watchlist scan.

#### 6c. Real email delivery

For Gmail: the account needs 2-Step Verification. Create an App Password at https://myaccount.google.com/apppasswords. Then replace the default `EMAIL_*` block in `.env`:

```ini
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=1
EMAIL_USE_SSL=0
EMAIL_HOST_USER=their.address@gmail.com
EMAIL_HOST_PASSWORD=their-16-letter-app-password
DEFAULT_FROM_EMAIL=CISO Brief <their.address@gmail.com>
```

For another SMTP relay (Microsoft 365, Amazon SES, Brevo, Mailgun): use the host, user and password it provides. Port 587 needs `EMAIL_USE_TLS=1`; port 465 needs `EMAIL_USE_SSL=1` and `EMAIL_USE_TLS=0`.

Apply and test:

```bash
docker compose up -d
docker compose exec web python manage.py check_email --to their.address@example.com
```

**Pass when:** it prints `Sent.` and the email arrives in their real inbox (check spam the first time).

### Phase 7: Wrap up

Tell the user:

- **App:** http://localhost · **Admin:** http://localhost/admin (create an admin with `docker compose exec web python manage.py createsuperuser`) · **Test inbox:** http://localhost:8025
- Briefs send automatically on each mailer's schedule while Docker is running. If the computer is off at the scheduled time, that brief is skipped, so for dependable delivery, run it on an always-on machine or server (see "Running it on a server" in the README).
- **Stop:** `docker compose down` (data is kept) · **Start:** `docker compose up -d` · **Update:** `git pull && docker compose up -d --build`
- Never share or commit `.env`.

---

### Troubleshooting (for the assistant)

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker: command not found` / `Cannot connect to the Docker daemon` | Docker not installed or not started | Install or start Docker Desktop; wait until it's running |
| `Bind for 127.0.0.1:80 failed: port is already allocated` | Another web server (IIS, Apache, Skype, another container) | Stop it, or change `127.0.0.1:80:80` to `127.0.0.1:8080:80` in `docker-compose.yml` and use http://localhost:8080. Also set `SITE_URL=http://localhost:8080` and add `http://localhost:8080` to `DJANGO_CSRF_TRUSTED_ORIGINS` in `.env`. |
| `POSTGRES_PASSWORD` error when starting | Not set in `.env` | Set it (Phase 3) |
| `web` restarting; logs show `InconsistentMigrationHistory` | An old database volume from a previous version | Fresh install with no data worth keeping: `docker compose down -v && docker compose up -d --build`. Get a yes first. |
| `worker` / `beat` logs say they're waiting for migrations | Normal for the first minute; `web` migrates first | Wait, then re-check `docker compose ps` |
| `CSRF verification failed` on sign-in | The URL in the browser doesn't match `DJANGO_CSRF_TRUSTED_ORIGINS` | Use exactly http://localhost, or add the URL in use to `.env` and run `docker compose up -d` |
| No confirmation email | Worker not running, or real SMTP misconfigured | `docker compose logs worker`; in the default setup the email is in Mailpit; or use the verify command in Phase 5 |
| `check_ai` says AI is off | `AI_BASE_URL` / `AI_API_KEY` blank, duplicated, or `.env` not reloaded | Fix `.env` (one line per setting), then `docker compose up -d` |
| Gemini `429` / `RESOURCE_EXHAUSTED` | Free-tier rate or daily limit | Wait a minute; try a Flash-Lite model in `AI_MODEL` |
| Gemini `400 ... not available in your country` | Free tier not offered in their region | Use Ollama or OpenAI instead |
| AI reply "not valid JSON" | The model cut off or is too small | Raise `AI_MAX_TOKENS` (for example 8192), choose a larger model, or lower `AI_MAX_ITEMS` |
| Ollama timeouts | CPU-only machine | `AI_TIMEOUT=600`, `AI_MODEL=qwen2.5:3b`, `AI_MAX_ITEMS=8` |
| Gmail `535 Username and Password not accepted` | Normal Gmail password used, or 2-Step Verification off | Use an App Password (Phase 6c) |
| Early-warning section empty | Sources haven't run yet, or no hits | Normal on day one; save the mailer to trigger a scan and check again later |
| Brief says "nothing matched" | Watchlist or technology too narrow for the last 24 h | Add more technology or industries in the builder, or check again after the next collection (every 4 h) |

Useful diagnostics:

```bash
docker compose ps
docker compose logs --tail=100 web
docker compose logs --tail=100 worker
docker compose exec web python manage.py check_ai --quick
docker compose exec web python manage.py check_email --to you@example.com
```
