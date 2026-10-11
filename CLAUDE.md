# CLAUDE.md

Orientation for a fresh Claude Code session picking up this project cold.
Keep this file current — when you make a change significant enough that a
new session would need to know about it (new module, new bug class fixed,
a dependency's behavior changed, scope changed), update this file in the
same turn, not as an afterthought.

For depth, don't duplicate here — point to:
- **[README.md](README.md)** — how to install and run everything (CLI, API, web UI, tests).
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the full build log: every design decision and *why*, every bug found and how it was fixed, phase by phase. Read this before changing core plumbing (`lantern/core/`) — the reasoning behind the SSRF guard, the cache design, the correlator, etc. is all there and usually non-obvious.

## What this is

Lantern: a modular OSINT aggregation tool. Give it a name, username,
email, domain, IP, or company; it classifies the input, dispatches to
every relevant data-source module concurrently, and reports what each
found with a confidence score. Built from the brief at
`/Users/skymajor/Desktop/7th Semester/SecAnalyst/Project/prompt.md`
(a coursework project) — public/keyless/free-tier sources only, no live
Tor access, SSRF-guarded, rate-limited, ToS-respecting.

## Full names are first-class input (added post-build — see ARCHITECTURE.md §4.16)

A full legal name like `John Doe` can now be used "to the fullest" across
every module, including the username ones. How it works, because it's not
obvious:

- A multi-word query still classifies as `PERSON + COMPANY` (**`classify()`
  is unchanged** — do not re-add `USERNAME` to the whitespace path; that
  was the §4.11 false-positive bug). Company modules (SEC EDGAR, GLEIF)
  and person modules (SearchApi, Wikipedia) already received full names
  that way.
- The username side is reached via **`PERSON` support on the username
  collectors**, not by feeding the raw string to site-checks:
  - **WhatsMyName** expands a name into likely handles
    (`lantern/core/names.py` → `username_variants()`: `johndoe`,
    `john.doe`, `jdoe`, …, capped at `DEFAULT_FANOUT_VARIANTS = 5` so one
    name doesn't fire 600×N requests) and checks each. Name-derived hits
    score `0.5` (vs `0.8` for a supplied handle) and carry `matched_handle`
    / `from_name`.
  - **`github_users`** and **`keybase`** match the name *server-side*
    (GitHub `/search/users`, Keybase `user_search`) — no handle guessing,
    one request. They also do exact-handle lookups on a plain `USERNAME`.
- The dispatcher's **`applicable()` now dedups**: a collector supporting
  both `USERNAME` and `PERSON` runs once per query (first supported type in
  `classification.types` order), not 2–3× against the same value.

## Current status: feature-complete, hardened post-build

All 6 planned phases are done, plus a round of post-build fixes driven by
actually running the live tool (see ARCHITECTURE.md §4.11–§4.17 for the
details). 184 backend tests passing. Nothing is a stub — if a module is
registered in `lantern/modules/registry.py`, it works end-to-end against
the real API.

**19 collectors**: WhatsMyName + GitHub user API + Keybase (username,
all keyless — and all three also accept a PERSON full name; see "Full
names" below), Gravatar (email→identity, keyless), XposedOrNot + HIBP
Pwned Passwords (email, keyless), RDAP + crt.sh (domain, keyless), Shodan
InternetDB/CVEDB + VirusTotal + AbuseIPDB (IP/domain infra — Shodan
keyless, VirusTotal and AbuseIPDB each configured and active), SEC EDGAR
+ GLEIF (company, keyless), Ransomware.live + Hudson Rock (darknet
Tier-1, both keyless — Hudson Rock despite the brief claiming it needs a
key), SearchApi.io + Wikipedia (general search, PERSON/DOMAIN only —
Wikipedia needs no key ever, SearchApi.io is configured and active).

The **four keyless enrichment collectors** added as "stage 1" (see
ARCHITECTURE.md §4.17) fill gaps nothing else covered: **dns-doh** (live
A/AAAA/MX/NS/TXT over DNS-over-HTTPS, DOMAIN), **wayback** (Internet
Archive first/last capture, DOMAIN), **gravatar** (email→display
name + linked social accounts, EMAIL), **ripestat** (IP→prefix/ASN/owner,
IP). All keyless, no card. **BGPView was the original pick for the IP one
but `api.bgpview.io` no longer resolves (NXDOMAIN) — replaced by RIPEstat
(RIPE NCC).** A planned "stage 2" of keyed-but-free sources (Hunter.io,
urlscan.io, OTX) is **not built yet**.

**Explicit type override (the input-type selector):** every search path
now takes an optional entity-type override that skips auto-detection —
`classify_as()` in `core/entities.py` forces one type (with a format check
for EMAIL/IP/DOMAIN; USERNAME/PERSON/COMPANY are free-form). Plumbed as
`Dispatcher.run/stream`'s `entity_type` param, the API's `/search?type=`,
the CLI's `--type`, and a dropdown in the web UI's SearchBar (default
"Auto-detect"). This is a precision/quota win (don't run person+company
modules on a known domain), **not** a performance one — `classify()`
itself was never a measurable cost.

**Brave Search and DuckDuckGo were removed by request** (see
ARCHITECTURE.md §4.14) — `brave_search.py`, `duckduckgo.py`, their tests,
and `Settings.brave_api_key` are all gone, not just unregistered. Brave
because its free tier no longer exists (see the pricing note below);
DuckDuckGo because its Instant Answer API was too narrow to be worth
keeping once VirusTotal/AbuseIPDB and a real SearchApi.io key gave
stronger coverage elsewhere. If either is ever wanted back, it's a
straightforward rebuild from `searchapi.py`'s pattern — don't assume the
old removed code is still around to resurrect, it isn't.

**VirusTotal** (`lantern/modules/infra/virustotal.py`) and **AbuseIPDB**
(`lantern/modules/infra/abuseipdb.py`) were added to strengthen
IP/domain-infra coverage ahead of the course presentation — both are
well-known names in the security community, both free with just a
community API key (no card), and both were verified against their
current (not stale) API docs before building, after discovering mid-
conversation that Brave had quietly removed its free tier (see
ARCHITECTURE.md §4.13) — the lesson that taught us not to trust
docs/comments without double-checking. VirusTotal: `{IP, DOMAIN}`, free
tier 500 req/day + 4
req/min. AbuseIPDB: `{IP}` only (no native domain endpoint), free tier
1,000 checks/day. Both keys are configured (`VIRUSTOTAL_API_KEY` /
`ABUSEIPDB_API_KEY` in `.env`) and verified live against a real IP
(`8.8.8.8`) — both returned clean, low-confidence reports as expected.

**Censys was considered and deliberately not built** — its 2025
migration to the "Censys Platform" API made the free-tier story murky:
free-tier Personal Access Tokens reportedly have no organization ID and
can't hit the search API, lookup-only endpoints may or may not work
without one depending on current rollout, and the lookup endpoints need a
versioned `Accept` header (`application/vnd.censys.api.v3.host.v1+json`)
on top of the bearer token. Rather than build against an unverified,
possibly-shifting free-tier shape, this was left for whoever actually has
a Censys account to confirm the current free-endpoint behavior firsthand
before writing the collector.

A Gemini-grounding search module (`gemini-search`) was built, tested, and
then **fully removed by request** — the Google Search grounding tool kept
returning `429 RESOURCE_EXHAUSTED` ("check your plan and billing") on the
user's account regardless of key/model fixes, confirmed as an
account-level entitlement issue outside this codebase's control, not
something worth carrying dead weight for. **`searchapi` (SearchApi.io,
`lantern/modules/search/searchapi.py`) was added as its practical
replacement** — a keyed, Google-results search with a **one-time
100-search trial (not a monthly allowance — see Known gaps)**,
`{PERSON, DOMAIN}` scoping, same cache-on-failure discipline below. If
`gemini-search` itself is ever wanted back, it's still a straightforward
rebuild (same pattern) — don't assume the old removed code is still
around to resurrect, it isn't.

Full stack: FastAPI SSE backend (`lantern/api/app.py`), Typer CLI
(`lantern/cli/main.py`), React+Vite+TS web UI (`web/`, Green Lantern
themed per explicit request — green accent, yellow "no results" state).

**Per-search module toggle** (see ARCHITECTURE.md §4.15): the web UI's
Settings panel lists every registered collector (fetched from `GET
/sources`) as a checkbox — "Modules." Unchecking one means it's skipped
on every search from then on, e.g. "only virustotal, no search engines."
Selection is stored client-side only (`useSettings.ts`'s
`disabledSources`, an opt-*out* list so a newly added collector defaults
to enabled rather than silently missing). Plumbed through as
`Dispatcher.applicable()`/`.stream()`'s new `enabled: set[str] | None`
param (`None` = unrestricted, unchanged default behavior), the API's
`/search?sources=...` repeated query param, and a matching `--source`
flag on the CLI (`lantern search <query> --source virustotal`, repeatable).

**Easter egg**: typing `oath` (exact, case-insensitive) into the web UI's
search box skips the real search entirely and plays a typewriter-style
reveal instead — `web/src/components/OathReveal.tsx` renders the lines
from `web/src/oath.ts` one character at a time. `web/src/oath.ts` now has
the user's real text (the Green Lantern oath) — it's no longer a
placeholder, don't change it unasked. Any other query behaves exactly as
before (`App.tsx`'s `runSearch` checks for the trigger before calling
`streamSearch` at all).

## Known gaps / things to pick up if asked

- **SearchApi.io has a key configured (`SEARCHAPI_API_KEY` in `.env`), ~99 of 100 free searches left.** Important: this pool is a **one-time trial, not a monthly allowance** — it never resets, unlike SerpApi's recurring monthly free quota. Burn what's left sparingly in dev — mock/replay saved JSON responses while iterating instead of hitting the live API — and keep a handful in reserve for the live demo, since once they're gone there's no refill without upgrading or a new account.
- **VirusTotal (`virustotal`) and AbuseIPDB (`abuseipdb`) are configured and active.** Both keys are in `.env`, both verified live against `8.8.8.8`. VirusTotal: 500 req/day + 4/min free tier. AbuseIPDB: 1,000 checks/day free tier, resets 00:00 UTC — mind the pace in dev the same way as any other rate-limited source.
- **"Stage 2" keyed-but-free sources (Hunter.io, urlscan.io, AlienVault
  OTX/LevelBlue) were researched and recommended but NOT built yet.** All
  three are free with email-only registration (no card); each would follow
  the existing `api_key_setting` graceful-skip pattern (like
  virustotal/searchapi). Hunter's free quota is small (treat like
  SearchApi.io — spend sparingly). GreyNoise Community was considered too
  but its API key needs a *business* email, so it's a poor fit.
- **BGPView is dead** — `api.bgpview.io` returns NXDOMAIN. The IP→ASN
  collector is **RIPEstat** (`ripestat`), not BGPView. Don't try to
  resurrect BGPView; if a second ASN source is ever wanted, RIPEstat's
  sibling data calls or Team Cymru are the leads.
- **GitLab was evaluated and not built as a name-search module** — its
  `/api/v4/users?search=<name>` now returns `403 Forbidden` without auth
  (only exact `?username=` works keyless, which is redundant with
  WhatsMyName's GitLab check). See ARCHITECTURE.md §4.16. Not worth a keyed
  rebuild for a capability we already have.
- **Censys was evaluated and not built** — its free-tier API access is in flux post-2025-platform-migration (see the paragraph above, and ARCHITECTURE.md §4.13). Pick this up only once someone has an actual Censys key in hand to verify the current free-endpoint shape against.
- **Brave Search and DuckDuckGo were built, then fully removed** (see ARCHITECTURE.md §4.14) — not disabled, not unregistered: the files, tests, and `brave_api_key` setting are gone. If either is wanted back, rebuild from `searchapi.py`'s pattern; don't look for the old files.
- **No frontend test suite.** Web UI verified by running the real stack, not automated tests. Would need Vitest + Testing Library if that's wanted.
- **Entity graph renders as a list in the web UI**, not a node-link diagram — same underlying data (`EntityGraph` JSON), simpler presentation. A real graph viz is a reasonable next step, not a correctness gap.
- **Ahmia was evaluated and dropped** — its clearnet search requires JS or the `.onion` address, both excluded by the brief's hard rules. See ARCHITECTURE.md §4.8.

## Conventions worth knowing before touching code

- **`lantern/modules/registry.py`** is the single source of truth for which collectors exist — CLI and API both read from `default_collectors()`. Adding a module means adding it there, not just writing the file.
- **Cache-on-failure discipline (important, bit everyone once already):** a collector's `_fetch`-style helper must let `httpx.HTTPError`/`ValueError` *propagate*, never catch-and-return-`None` internally. `Cache.get_or_set` can't tell "request failed" apart from "confirmed empty result" — both come back `None` — so a caught exception gets cached as a false negative for the full TTL. The catch belongs at the `get_or_set(...)` call site, outside the cached path. For collectors with concurrent fan-out (`asyncio.gather` over several IPs/CVEs/records), the catch must be *inside* the per-item call, not propagated to the outer gather, or one item's failure cancels every sibling's result too (see ARCHITECTURE.md §4.12 and the Phase 2 WhatsMyName bug for the original instance of this class of bug).
- **A literal `404` is only a cacheable "confirmed not found" for sources where that's actually true** (RDAP, SEC, Wikipedia, Shodan, Hudson Rock). `ransomware_live` is the one exception — its `404`s are documented live-observed noise (same request failing then succeeding moments later), so it treats all non-2xx as transient, never cacheable.
- **`get_settings()` is `@lru_cache`'d** for real process lifetimes. Tests use an autouse fixture (`tests/conftest.py`) that clears the cache and stubs `load_dotenv()` per test — don't call `get_settings()` directly in a new test without it.
- **The web UI's SSE client is hand-rolled** (`web/src/api.ts`), not the browser's native `EventSource` — `EventSource` can't carry an `Authorization` header and the API requires one on every request. Don't "simplify" this back to `EventSource`.
- **`SSRFGuardTransport` pins every request to its resolved IP** post-DNS-check (closes a rebinding TOCTOU). Collectors only ever get `ctx.http`, pre-built with this transport — never construct a raw `httpx.AsyncClient` in a collector.
- **`classify()` drops `USERNAME` from the ambiguous candidate set when the query has whitespace** — real usernames don't contain spaces; this was a real bug (full names were getting checked against WhatsMyName's 600 sites and returning noise). Full names still reach the username collectors, but via **`PERSON` support + `username_variants()`**, not by re-adding `USERNAME` here (see the "Full names" section above). Don't undo this guard.
- **A collector may support both `USERNAME` and `PERSON`** (`whatsmyname`, `github_users`, `keybase`). `Dispatcher.applicable()` dedups so each runs once per query — if you add a collector spanning several of the ambiguous trio, rely on that dedup rather than hand-picking a type.
- **Fan-out collectors that expand a name into handles must cap the expansion** (`DEFAULT_FANOUT_VARIANTS`) and share one semaphore across the whole handle×target fan-out — WhatsMyName's ~600 sites × N handles is the thing to keep bounded.
- **Search-scoped collectors (`searchapi`, `wikipedia`) are deliberately scoped to `{PERSON, DOMAIN}` only**, never `USERNAME`/`COMPANY` — those are already covered elsewhere, and including them would make a general-search module fire 2–3x on one ambiguous query.
- **New collectors show up in the web UI's module toggle automatically** — `GET /sources` just reflects `Dispatcher.collector_names`, which reads from whatever's registered in `registry.py`. No separate list to maintain for the toggle UI.

## Quick commands

```bash
# Backend tests
.venv/bin/pytest tests/ -v

# Run the API (binds 127.0.0.1:8000)
.venv/bin/python -m lantern.api.app

# Run the web UI (needs the API running)
cd web && npm run dev

# Run the CLI directly
.venv/bin/lantern search "<query>"
```

`.env` already has `CONTACT_EMAIL` and `API_BEARER_TOKEN` (`dev-local-token`
locally) set. See `.env.example` for the full list and what's optional.
