# Lantern

Lantern is a modular OSINT aggregation tool. Give it a name, username,
email, domain, IP, or company, and it classifies the input, dispatches the
query to every relevant data-source module concurrently, and reports what
each source found with its own confidence score and link back to the
source.

This README covers what's runnable today. For the full build log —
architecture, why things are built the way they are, bugs found along the
way, and what's still ahead — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Ethics / legal

Lantern reads and aggregates **public data only** — keyless or free-tier
APIs, plus Tier-1 clearnet darknet intelligence (not live Tor access).
Respect each source's Terms of Service and documented rate limits. Know
your jurisdiction's law before using this against a person or
organization without their consent. This tool does not bypass
authentication, scrape private data, or access anything behind a login.

## What's implemented

| Area | Sources |
|---|---|
| Username | WhatsMyName (checks ~600+ sites) |
| Email | XposedOrNot (breach check + analytics), HIBP Pwned Passwords (standalone, see below) |
| Domain | RDAP (via IANA bootstrap), crt.sh (cert-transparency subdomains) |
| Infra (IP/domain) | Shodan InternetDB + CVEDB enrichment (keyless), VirusTotal (IP/domain reputation, optional key), AbuseIPDB (IP abuse reports, optional key) |
| Company | SEC EDGAR, GLEIF (LEI + parent relationships) |
| Darknet (Tier-1, clearnet only) | Ransomware.live (victims/groups), Hudson Rock Cavalier (infostealer exposure) |
| Search (PERSON/DOMAIN only) | Wikipedia (free, no key, ever) + SearchApi.io (optional key, Google-results search) |

Also implemented: a correlator (groups Findings into Entities, requiring
a corroborating pivot — shared data field or identical cited URL — before
merging same-named-but-different things; see
[docs/ARCHITECTURE.md §4.9](docs/ARCHITECTURE.md#49-correlator-and-the-fastapi-sse-endpoint-phase-5)),
a FastAPI SSE endpoint, and a React + Vite + TypeScript web UI (Green
Lantern themed).

Ahmia was evaluated and dropped for this version — see
[docs/ARCHITECTURE.md §4.8](docs/ARCHITECTURE.md#48-darknet-phase-4--tier-1-clearnet-only-one-source-dropped)
for why.

## Install

Requires Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Set up `.env`

Copy the example and fill it in:

```bash
cp .env.example .env
```

| Variable | Required? | Used for |
|---|---|---|
| `CONTACT_EMAIL` | **Required** | Sent in the User-Agent on every outbound request. Several sources (SEC EDGAR explicitly) return `403` without a real one. |
| `API_BEARER_TOKEN` | **Required to run the API** | Authenticates every API request, even local ones (the whole API, not just `/search` — the auto docs routes are disabled rather than left open). The CLI never reads this. |
| `VIRUSTOTAL_API_KEY` | Optional | Enables `virustotal` (IP/domain reputation). Free community key, no card — [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us). |
| `HUDSONROCK_API_KEY` | Optional | Unused — the Hudson Rock module uses Cavalier's free, keyless community endpoints. Kept here in case that ever changes. |
| `SEARCHAPI_API_KEY` | Optional | Enables `searchapi` (Google-results search via SearchApi.io). Free tier: **100 searches total, one-time trial — does not reset monthly** — [searchapi.io](https://www.searchapi.io/). |
| `ABUSEIPDB_API_KEY` | Optional | Enables `abuseipdb` (IP abuse/reputation reports). Free tier: 1,000 checks/day, resets 00:00 UTC — [abuseipdb.com](https://www.abuseipdb.com/). |
| `CACHE_PATH` | Optional (default `lantern_cache.db`) | SQLite file for the per-source TTL cache. |

`wikipedia` needs no key at all, ever — it's always active for PERSON/DOMAIN queries.

Brave Search and DuckDuckGo were built, then removed — Brave's free Search
API tier no longer exists (metered billing now, real card required), and
DuckDuckGo's Instant Answer API was too narrow to be worth keeping
alongside VirusTotal/AbuseIPDB/SearchApi.io. See
[docs/ARCHITECTURE.md §4.14](docs/ARCHITECTURE.md) for the full story.

## Run the CLI

```bash
lantern search "torvalds"
lantern search "example.com"
lantern search "8.8.8.8"
lantern search "Apple Inc"
lantern search "alice@example.com"
```

A query is classified automatically (email / IP / domain, or — if
ambiguous — username, person, *and* company all at once), then every
module that supports that type runs concurrently. Results stream in as
each source responds.

Restrict which collectors run with `--source` (repeatable):

```bash
lantern search "8.8.8.8" --source virustotal
```

Skip auto-detection and force the input type with `--type`
(`email`/`ip`/`domain`/`username`/`person`/`company`) — useful when a value
is ambiguous and you already know what it is, so only that type's modules
run:

```bash
lantern search "John Doe" --type person
```

Standalone utilities (not part of the entity-search pipeline — see the
architecture doc for why):

```bash
lantern check-password "some password"   # HIBP Pwned Passwords, k-anonymity only
lantern darknet recent --limit 20        # Latest disclosed ransomware victims
lantern darknet groups                   # Known ransomware groups
```

## Run the API

```bash
.venv/bin/python -m lantern.api.app
```

Binds to `127.0.0.1:8000` by default. One endpoint:

```bash
curl "http://127.0.0.1:8000/search?q=8.8.8.8" \
  -H "Authorization: Bearer $API_BEARER_TOKEN"
```

Streams Server-Sent Events — a `finding` event per result as each module
responds, then a final `done` event with the correlated entity graph
(`{"nodes": [...], "edges": [...]}`). Every route requires the bearer
token from `.env`, including local requests; there's no interactive
`/docs` page by design (see the architecture doc for why).

## Run the web UI

Requires Node.js. The API must already be running (see above) — the web
UI is a pure client that talks only to it.

```bash
cd web
npm install
npm run dev
```

Opens at `http://localhost:5173`. On first load, click **Settings** (top
right) and set the API URL (defaults to `http://127.0.0.1:8000`) and the
same bearer token from your `.env` — stored only in that browser's
`localStorage`, never sent anywhere but your own local API.

The same Settings panel lists every registered collector as a **Modules**
checkbox list — uncheck any you don't want running, e.g. "only
`virustotal`, skip the search engines." The choice is per-browser and
applies to every search until changed again; a collector added later
shows up checked (enabled) by default.

Single search box, results stream in grouped by source as each module
responds, with a per-source pending/found/no-results chip row above them.
A **Relationships** section appears when the correlator's entity graph
has any edges. **Copy JSON** copies the raw findings + graph to the
clipboard. Light/dark follows the OS; keyboard focus rings and mobile
layout are both handled (see `web/src/styles/tokens.css` for the design
tokens, and [docs/ARCHITECTURE.md §4.10](docs/ARCHITECTURE.md#410-brave-search-and-the-web-ui-phase-6)
for how the SSE client works around `EventSource` not supporting auth
headers).

## Run the tests

Backend:

```bash
.venv/bin/pytest tests/ -v
```

184 tests, no network required — every collector is tested against
mocked HTTP (`respx`), with the SSRF guard tested separately and
exhaustively on its own, and the correlator tested against synthetic
ambiguous-name scenarios since live data rarely exercises that path on
its own.

Web UI:

```bash
cd web && npm run build   # type-checks + production build
npm run lint
```

No frontend test suite yet (component tests would need Vitest +
Testing Library, not set up in this version) — verified instead by
running the real API and driving the real UI end to end.
