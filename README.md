# Vantis

Modular, plugin-based vulnerability scanner combining:
- 🔍 **Reconnaissance** — subdomain enumeration (crt.sh), common-port scanning, technology fingerprinting, **TLS/SSL audit**, **subdomain takeover**
- 🌐 **Web testing** — security headers, reflected XSS, SQL injection, **path traversal/LFI**, **SSTI**, **CORS misconfig**, **open redirect**, **dangerous HTTP methods**, exposed paths, **content discovery**, **secrets in JS** (all non-destructive detection)
- 🧩 **CVE detection** — Nuclei-style YAML template engine (22 templates) + **version→CVE** mapping

Built for **bug bounty** and **authorized** penetration testing.

Capabilities: an **injection-point crawler** (links, GET forms, robots/sitemap, bounded BFS, Wayback), **authenticated scanning** (session headers/cookies), **concurrent** module execution, exports to **JSON / HTML / Markdown / PDF / SARIF**, **finding triage** (false-positive management), **scan diffing**, **scheduled recurring scans**, and **webhook notifications**.

Vantis can be used two ways:
- **CLI** — a standalone command-line scanner (no web dependencies).
- **Web stack** — a **REST API** (FastAPI) and a **React interface** to launch scans from the browser, follow results **in real time** (WebSocket), and browse history.

<!-- SCREENSHOT -->
<!-- Replace this line with a screenshot/GIF of the interface, e.g.:
     ![Vantis interface](docs/screenshot.png) -->

## ⚠️ Legal notice — read before any use

**This project must only be used against targets you are explicitly authorized to test**:
a bug bounty program whose scope covers the target, a signed pentest agreement, or an asset you own yourself.

Scanning a system without authorization is **illegal in most jurisdictions**, including aggressive passive reconnaissance and non-destructive testing. The tool shows a warning and requires an explicit confirmation before every scan — this is not cosmetic, it is a deliberate safeguard.

That safeguard exists everywhere:
- **CLI** — interactive authorization prompt (or the `--yes-i-am-authorized` flag you type yourself).
- **API** — the `"authorized": true` field is **mandatory** in `POST /api/scans`; the request is rejected (400) otherwise.
- **Web interface** — an explicit "I confirm I am authorized to test this target" checkbox, non-bypassable: the *Launch scan* button stays disabled until it is checked.

The author accepts no liability for unauthorized use of this tool.

## Installation

### Option A — CLI only (lightest)

No web dependencies, just Python ≥ 3.10:

```bash
git clone https://github.com/<your-user>/vantis.git
cd vantis
pip install -e .
```

Usage:

```bash
# Full scan (recon + web + cve)
vantis --target https://authorized-example.com

# Web + cve only, with HTML output
vantis --target https://authorized-example.com --modules web,cve --output report.html

# Widen the scope to known subdomains
vantis --target example.com --scope example.com,api.example.com,staging.example.com

# Verbose mode + JSON report
vantis --target https://authorized-example.com -v --output report.json
```

At runtime the tool asks for an explicit authorization confirmation before launching any active test.

### Option B — Full web stack via Docker (easiest to demo)

A single command builds and launches the API and the interface:

```bash
docker compose up --build
```

Then open:
- **Web interface**: <http://localhost:8080>
- **REST API**: <http://localhost:8080/api>
- **Interactive docs (Swagger)**: <http://localhost:8080/api/docs>

The frontend (nginx) serves the app and reverse-proxies the API, including the real-time WebSocket — the browser only ever talks to a single origin, with no CORS to configure. The SQLite database is persisted in a Docker volume.

### Option C — Web stack in development (hot-reload)

For development, run the two servers separately:

```bash
# 1) API (terminal 1)
pip install -e ".[api,dev]"
alembic upgrade head
uvicorn api.main:app --reload            # http://localhost:8000  (docs: /docs)

# 2) Frontend (terminal 2)
cd web
npm install
npm run dev                              # http://localhost:5173
```

The Vite dev server proxies `/api` (REST + WebSocket) to `http://localhost:8000`.

## REST API — overview

| Method | Route | Purpose |
|--------|-------|---------|
| `POST` | `/api/scans` | Launch a scan (`authorized: true` required) → `202` + `scan_id` |
| `GET` | `/api/scans` | Paginated history |
| `GET` | `/api/scans/{id}` | Status + progress (current module, findings) |
| `GET` | `/api/scans/{id}/findings` | Findings, filterable with `?severity=`, `?module=`, `?status=` |
| `PATCH` | `/api/scans/{id}/findings/{fid}` | Triage a finding (`open` / `false_positive` / `confirmed`) |
| `GET` | `/api/scans/{id}/report?format=json\|html\|md\|pdf\|sarif` | Export the report |
| `GET` | `/api/scans/{id}/diff?against={id}` | Compare two scans (new / fixed / unchanged) |
| `DELETE` | `/api/scans/{id}` | Cancel a running scan, or delete history |
| `WS` | `/api/scans/{id}/live` | Real-time stream of findings during the scan |
| `POST/GET/PATCH/DELETE` | `/api/schedules` | Manage recurring scans (creation requires `authorized: true`) |

The scan runs in the background; the API responds immediately and progress is pushed live over the WebSocket.

## Configuration (environment variables)

The API is configured entirely through the environment (or a `.env` file at the repo root, gitignored). Everything has sensible defaults for local development.

| Variable | Default | Purpose |
|----------|---------|---------|
| `VANTIS_DATABASE_URL` | `sqlite:///./vantis.db` | Database. For MySQL/WAMP: `mysql+pymysql://root:@localhost:3306/vantis` (requires `pip install -e ".[api,mysql]"`) |
| `VANTIS_CORS_ORIGINS` | Vite origins | Allowed origins (never `*`), comma-separated |
| `VANTIS_SCAN_RATE_LIMIT` | `5/hour` | Scan-creation limit per IP |
| `VANTIS_API_KEY` | *(empty = disabled)* | If set, **authentication is required**: `X-API-Key` header (and `?key=` for the WebSocket). On the frontend, provide the same value via `VITE_API_KEY`. **Set this before any network exposure.** |
| `VANTIS_BLOCK_PRIVATE_TARGETS` | `false` | If `true`, rejects private/loopback/reserved IP targets (basic anti-SSRF). Off by default because authorized internal pentests legitimately target internal hosts. |
| `VANTIS_SCAN_WORKERS` | `4` | Concurrent workers for web/cve modules within one scan (recon stays sequential). |
| `VANTIS_WEBHOOK_URL` | *(empty = disabled)* | If set, POST a summary to this webhook (Slack/Discord/generic) when a scan finishes with findings at/above the threshold. |
| `VANTIS_WEBHOOK_MIN_SEVERITY` | `high` | Minimum severity that triggers a webhook notification. |

**Authenticated scanning** (CLI): `-H 'Authorization: Bearer …'` and `-C 'session=…'` (both repeatable). API: `headers`/`cookies` fields on `POST /api/scans` (used in-memory only, never stored). **Concurrency** (CLI): `--workers N`.

### Using MySQL / MariaDB (e.g. WAMP + phpMyAdmin)

```bash
# 1) Driver
pip install -e ".[api,mysql]"

# 2) Create the "vantis" database (utf8mb4_unicode_ci collation) in phpMyAdmin

# 3) Point the API at it (in .env), then migrate
#    VANTIS_DATABASE_URL=mysql+pymysql://root:@localhost:3306/vantis
alembic upgrade head
```

SQLite remains the default: no extra installation is required to get started.

> **After pulling updates, apply new migrations:** `alembic upgrade head`.
> If the schema is behind, scans can complete with **0 saved findings** — Vantis
> now detects this and marks such scans **failed** with a message telling you to
> run the migration, instead of silently reporting an empty result.

## Architecture

```
vantis/
├── core/
│   ├── engine.py         # orchestrator, module discovery, authorization gate
│   ├── plugin_base.py    # ScanModule contract every module implements
│   ├── target.py         # target and scope validation (keeps path/query)
│   └── report.py         # Finding model + JSON/Markdown/HTML/PDF export
├── modules/
│   ├── recon/            # subdomain_enum, port_scan, tech_detect
│   ├── web/              # headers_check, xss_check, sqli_check, exposed_paths
│   └── cve/              # template_engine.py (engine) + runner.py (module)
└── utils/
    ├── http_client.py    # shared HTTP client, rate-limited, identifiable User-Agent
    └── crawler.py        # light injection-point discovery (links + GET forms)

api/                        # REST API (FastAPI) — adapts the engine for the web
├── main.py                 # FastAPI app, CORS, rate-limiting, lifecycle
├── routers/scans.py        # /api/scans endpoints + WebSocket
├── models.py / schemas.py  # SQLAlchemy ORM / Pydantic schemas
├── scan_runner.py          # background execution (thread pool)
└── websocket_manager.py    # real-time event broadcast

web/                        # React interface (Vite + TypeScript + Tailwind)
├── src/pages/              # NewScan, ScanLive, ScanReport, ScanHistory
├── src/components/         # AuthorizationGate, FindingCard, SeverityChart…
└── src/hooks/              # useScans (react-query), useScanWebSocket
```

The `vantis/` library stays the **source of truth**: the API and interface only expose it. The engine only gained an optional observation hook (`progress_callback`), backward-compatible with the CLI.

## Tests

```bash
# Backend (engine + API) — pytest
pip install -e ".[api,dev]"
pytest

# Frontend — Vitest + React Testing Library
cd web && npm test
```

API tests use a fake engine: **no network traffic is emitted** during the test suite. The `AuthorizationGate` test explicitly verifies that the launch button stays disabled until the authorization box is checked.

## CI/CD — GitHub Action

Vantis ships a composite GitHub Action (`action.yml` at the repo root) that runs a scan and uploads the results as SARIF to GitHub code scanning:

```yaml
- name: Run Vantis
  uses: NathaneSebban/Vantis@main
  with:
    target: https://staging.example.com   # must be a target you are authorized to scan
    modules: recon,web,cve
    fail-on-severity: high                # fail the job on high/critical findings; "none" to never fail
```

`.github/workflows/vantis-scan-example.yml` in this repo is a ready-to-copy example. It is deliberately **`workflow_dispatch`-only** (never runs on push/PR/schedule) and requires typing `authorized: yes` when triggering it — Vantis actively probes whatever target it's given, so a CI workflow must never fire automatically against a target nobody explicitly confirmed.

## Writing a new module

Just add a class under `vantis/modules/<category>/` that inherits from `ScanModule`:

```python
from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

class MyModule(ScanModule):
    name = "my-module"
    category = "web"  # or "recon" / "cve"

    def run(self) -> list[Finding]:
        # ... module logic ...
        return [Finding(module=self.name, title="...", severity=Severity.LOW, target=str(self.ctx.target))]
```

The engine discovers it automatically at startup — no other change is needed.

## Writing a new CVE template

Templates are YAML files under `templates/cve/`. They describe a request and a matcher — see the provided examples. By design a template can only perform a **detection** request (status, header, response content); it cannot encode multi-step exploitation.

## Roadmap

- [x] Subdomain takeover detection
- [x] Authentication support (cookies/tokens) to scan authenticated areas
- [x] SARIF export for CI/CD integration
- [x] Secret detection in exposed JavaScript
- [x] TLS/SSL audit, content discovery, CORS / open-redirect / HTTP-method checks
- [x] Path traversal / LFI and SSTI detection
- [x] Version→CVE mapping; deeper crawler (robots/sitemap/BFS/Wayback)
- [x] Concurrent engine; finding triage; scan diffing; scheduled scans; webhooks
- [ ] Distributed workers (Celery/Redis) — the ScanManager is structured for it; needs a broker to run
- [ ] Out-of-band interaction server for blind XSS/SSRF — needs a public callback host
- [ ] Adaptive rate-limiting based on 429 responses

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs are welcome, especially for new modules or CVE templates. Please keep the project's spirit: non-destructive detection only.
