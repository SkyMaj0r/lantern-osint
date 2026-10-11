# Lantern — architecture & build log

This document explains what has been built so far, why it's structured the
way it is, what broke during development and how it was fixed, and what's
still ahead. It's the long-form companion to the README (which is just
run instructions). Written as a running log, phase by phase, so it stays
useful as a record of *why* decisions were made, not just what the code
currently looks like.

Scope reminder: public, keyless/free-tier sources only, plus a handful of
free-key sources (SearchApi.io, VirusTotal, AbuseIPDB — see §4.13).
Hudson Rock turned out not to need a key at all, see §4.8. Two modules
were built and later fully removed: a Gemini-grounding search module
(§4.11's update note) and, later, Brave Search and DuckDuckGo (§4.14). No
live Tor access anywhere in this version.

---

## 1. The shape of the system

Lantern is a pipeline, not a monolith. A query goes through four stages:

```
 "torvalds"                 classify()                 dispatcher.stream()
 "8.8.8.8"        ─────►   EntityType(s)    ─────►   Collector.collect()
 "example.com"              (one or more)              (concurrent, per-type)
 "Apple Inc"                                                   │
                                                                ▼
                                                   list[Finding] (streamed)
                                                                │
                                                                ▼
                                          (Phase 5: Correlator → Entity graph)
```

1. **Classify** (`lantern/core/entities.py`) — turn the raw string into one
   or more candidate `EntityType`s.
2. **Dispatch** (`lantern/core/dispatcher.py`) — for each candidate type,
   run every `Collector` that declares support for it, concurrently.
3. **Collect** (`lantern/modules/**`) — one file per data source, each
   implementing the same `Collector` interface. Adding a source never
   touches the core.
4. **Correlate** (§4.9) — merge `Finding`s into `Entity` objects with a
   confidence score, requiring a corroborating pivot before merging two
   findings into one entity.

Everything hangs off two pieces of shared state, assembled once per search
into a `Context` (`lantern/modules/base.py`):

- `http`: an SSRF-guarded `httpx.AsyncClient` — collectors never construct
  their own client, so the guard can't be bypassed by a module author
  forgetting to opt in.
- `cache` / `settings`: the SQLite TTL cache and the `.env`-backed config.

## 2. Core plumbing (Phase 1)

### 2.1 The Collector contract

Locked early, per the brief, before any real module existed:

```python
class Collector(ABC):
    name: str
    supported_types: set[EntityType]
    rate_limit: RateLimit
    requires_key: bool = False

    async def collect(self, query: str, entity_type: EntityType, ctx: Context) -> list[Finding]: ...
```

`Finding` is intentionally dumb — `source`, `entity_type`, `value`, a free
`data: dict`, `confidence`, optional `url`, `discovered_at` — so the
correlator (Phase 5) never has to special-case a source. Everything
source-specific lives in `data`.

### 2.2 SSRF guard — and why it does more than the brief's letter

The hard rule was: block `10/8`, `172.16/12`, `192.168/16`, `127/8`,
`169.254/16`, `::1`, `fc00::/7`. `lantern/core/ssrf.py` blocks those, plus
three extras, disclosed rather than silently added:

- `0.0.0.0/8` and `fe80::/10` (link-local IPv6) — obvious gaps in the
  literal list that a real attacker would reach for immediately.
- IPv4-mapped IPv6 unwrapping (`::ffff:10.0.0.1` → `10.0.0.1` before the
  check) — otherwise a trivially-encoded private IPv4 address sails
  through the IPv6 branch untouched.

**The harder problem was DNS rebinding.** A naive guard resolves the
hostname, checks the IP, and *then* lets httpx make its own independent
DNS lookup to actually connect — two lookups, two chances for the answer
to differ (TOCTOU). `SSRFGuardTransport` closes that gap by resolving the
host itself, validating the result, then **pinning the connection to that
exact IP**: it rewrites `request.url` to the validated IP literal, and
sets the original hostname back as the `Host` header and the TLS SNI
(`request.extensions["sni_hostname"]`) so the request still looks correct
to the server and to certificate validation. One resolution, one
connection, no window for a second lookup to return something different.

Every collector gets this transport through `ctx.http` — there's no way
for a module to accidentally use an unguarded client, because the only
client that ever exists is the one the CLI/API builds via
`build_guarded_client()` and threads through `Context`.

### 2.3 Rate limiting — two layers, on purpose

`RateLimiterRegistry` + `SourceRateLimiter` (sliding window) throttle how
often the **dispatcher** invokes a given collector's `collect()`. That's
necessary but not sufficient: several collectors fan out into *multiple*
real HTTP requests inside a single `collect()` call (WhatsMyName hits
hundreds of sites; XposedOrNot, Shodan, SEC EDGAR, and GLEIF each make 2+
calls per query, sometimes with concurrent sub-fan-out on top). The
dispatcher-level limiter can't see any of that internal traffic.

So any collector whose own `collect()` can issue more than one real
request against the same backend keeps a **second**, private
`SourceRateLimiter` instance and calls `acquire()` before each internal
HTTP call. This is the pattern in `XposedOrNotCollector`,
`ShodanInfraCollector`, `SecEdgarCollector`, and `GleifCollector`. RDAP and
crt.sh don't need it — they make at most one real call per `collect()`
(the IANA bootstrap and SEC ticker files are cached, so after the first
hit they're not "real calls" either).

### 2.4 Cache — a bug found by just thinking it through

`Cache.get(source, key)` returns `None` for "not cached." But what if the
*correct, legitimate* value is `None` or empty — "no breaches found for
this email," "this domain isn't RDAP-registered"? That's also `None`.
Without fixing this, every clean/negative result would be re-fetched on
every single call, defeating the entire purpose of caching those cases —
arguably the *common* case for most queries.

Fixed with `Cache.get_or_set(source, key, ttl_seconds, fetch)`: it wraps
whatever `fetch()` returns in `{"value": ...}` before storing, so a stored
`None` is distinguishable from "nothing stored." Added as a new method
rather than changing `get`/`set`'s behavior, so the already-tested Phase 1
cache contract didn't need to change. Every Phase 3 module uses
`get_or_set`, not raw `get`/`set`.

### 2.5 Settings / `.env`

`CONTACT_EMAIL` is required and fails loud (`SettingsError`) if missing —
several sources (SEC EDGAR explicitly) return `403` without a real contact
email in the User-Agent, so silently running with a blank one would
produce confusing failures far from the actual cause.
`VIRUSTOTAL_API_KEY` / `HUDSONROCK_API_KEY` / `BRAVE_API_KEY` are
optional; nothing uses them yet.

`API_BEARER_TOKEN` was originally required alongside `CONTACT_EMAIL`, but
that meant `lantern search ...` — which never reads it — refused to run
without a token for an API that doesn't exist yet. Caught this while
writing the README's required/optional table and fixed it: the field is
now optional on `Settings`, and enforcing its presence becomes the
not-yet-built API's own job at startup, not every CLI invocation's.

## 3. WhatsMyName — the end-to-end proof (Phase 2)

Fetches `wmn-data.json` from the WebBreacher/WhatsMyName repo (cached 24h
via `Cache`), checks each of its ~600+ site entries concurrently (capped
at 20 in flight — a plain politeness measure; nothing in the brief
requires it, but firing 600 simultaneous requests at unrelated third-party
sites is a bad way to behave), and applies each entry's own `e_code` /
`e_string` detection rule.

**One assumption flagged, not resolved**: the brief calls the file
`wmn-dat.json`; the actual file in the repo (as far as I know) is
`wmn-data.json`. Used the latter since the former 404s. Worth confirming
if the live run ever starts failing to fetch it — repos get restructured.

### 3.1 Bug: one dead site took down all ~600 results

First live run against a real username crashed the entire collector. The
dispatcher's top-level catch-all logged `whatsmyname: collect() failed`
and returned zero findings — for a query that, re-run after the fix,
produced 78 real matches.

Root cause: `_check_site`'s `except httpx.HTTPError` didn't catch
`SSRFError` — a *different* exception type, raised by the SSRF guard's own
transport when one site's domain failed to resolve (dead domain — common
across a 600-entry dataset of mostly-unmaintained community checks). That
one `SSRFError` propagated out of one coroutine inside
`asyncio.gather(*600 coroutines)`, which — by default — cancels every
sibling task and re-raises the first exception. One unmaintained site
checker effectively took out all 600.

Fixed by widening the catch to bare `Exception` in that one call site —
deliberately broad, because this is exactly the shape of problem where
broad-but-contained is correct: a single arbitrary third party out of
hundreds must never affect the others, regardless of *how* it fails (DNS,
TLS, timeout, connection reset, or anything else not yet seen). Added a
regression test using a plain `RuntimeError` side effect, specifically
because the original bug involved a non-`HTTPError` exception — a test
using `httpx.ConnectError` wouldn't have caught the regression.

**Lesson carried forward**: any collector with internal fan-out across
many independent third parties needs the same broad, narrowly-scoped
catch. Checked against the others built since — Shodan's per-CVE fan-out
and GLEIF's per-record parent lookups both already catch broadly at the
per-item level, for the same reason.

## 4. email / domain / infra / company (Phase 3)

### 4.1 The Pwned Passwords architectural mismatch

HIBP Pwned Passwords checks a **password**, not an entity `classify()` can
ever produce (`EMAIL | IP | DOMAIN | USERNAME | PERSON | COMPANY` — never
"password"). Forcing it into the `Collector` interface would mean either
inventing a fake entity type that means something different everywhere
else, or having a `collect()` whose `query` parameter is secretly a
password while every other collector's is a search target — a trap for
whoever edits this code next.

Flagged this rather than guessing, and built it as what it actually is: a
plain function (`check_password` in
`lantern/modules/email/pwned_passwords.py`) called directly from its own
CLI command (`lantern check-password <password>`) and, later, its own API
route — never through `classify()` / `Dispatcher`. Tests assert the full
password and even the un-hashed suffix never appear in the outbound
request URL, only the 5-char prefix.

### 4.2 RDAP: per-TLD server resolution

WHOIS was sunset for gTLDs 2025-01-28, replaced by RDAP. RDAP isn't one
server — every TLD operator runs its own, so the right one has to be
looked up per query from IANA's bootstrap registry
(`data.iana.org/rdap/dns.json`, cached 24h) rather than hardcoded.

### 4.3 crt.sh flakiness, observed live, not hypothesized

During real end-to-end testing (not a mocked test), a live query to
`crt.sh` returned a `502 Bad Gateway` — a known characteristic of that
free community service under load, not a bug on our side. The collector's
existing error handling absorbed it cleanly: logged, returned `[]`, and
the *other* modules running concurrently for the same query (RDAP, infra)
were unaffected. This is the "graceful degradation everywhere" hard rule
working exactly as intended, caught in the wild rather than in a unit
test.

### 4.4 infra/: resolving a domain to an IP is not an SSRF-relevant fetch

Shodan InternetDB only accepts IP addresses, but the brief lists infra/ as
applying "for IP and domain." So for a domain query, the collector first
resolves it to its IP(s) via plain `getaddrinfo` — a local DNS lookup, not
an HTTP fetch. This deliberately does **not** go through
`SSRFGuardTransport`: the guard exists to stop us from *fetching content
from* an attacker-influenced address, not to restrict which IP strings we
hand to a third party's API as a query parameter. The actual HTTP request
this module makes always goes to `internetdb.shodan.io` / `cvedb.shodan.io`
— fixed, trusted hosts — never to the resolved IP itself.

### 4.5 GLEIF parent relationships — done properly, not stubbed

The brief asks GLEIF to surface "corporate parent relationships," not just
a note that one exists. Implemented as a bounded follow-up fetch: when a
record's `relationships.ultimate-parent` link is present, fetch it and
pull the parent's legal name into `data["parent_name"]`, cached
independently so repeat queries don't re-fetch it. Bounded by
`MAX_RESULTS` (5) so one query can't fan out into an unbounded chain of
follow-up calls.

### 4.6 Judgment calls made without stopping to ask

Rate limits and cache TTLs for sources with no documented number (RDAP,
crt.sh, Shodan, GLEIF) were picked conservatively and are isolated as
named constants at the top of each module file — easy to find, easy to
change, each one a one-line edit. Not worth a round-trip per number; worth
disclosing here instead.

### 4.7 A CLI side effect worth knowing about

Typer auto-promotes a single registered command to be the app's root
command — no subcommand name needed. That's why `lantern mralanorange`
worked in Phase 2 testing. Adding `check-password` as a second command in
Phase 3 turned that off: invocation is now `lantern search <query>` and
`lantern check-password <password>`, explicitly. Mentioned here because
it's the kind of thing that looks like a regression if you don't know it
was Typer's own behavior changing underneath, not a bug introduced by the
new command.

## 4.8 darknet/ (Phase 4) — Tier-1 clearnet only, one source dropped

Before writing anything, verified all three sources live rather than
building against the brief's descriptions — the same lesson as the
WhatsMyName filename, applied up front this time.

**Ahmia — dropped for this version, not built.** Direct testing against
the real clearnet site (`curl` with a realistic browser UA, referer, and
cookies) showed every `/search/` request 302-redirecting back to `/`, with
an `Onion-Location` header pointing at Ahmia's own `.onion` mirror, and the
homepage stating outright: *"we have not deployed non-JavaScript version
of Ahmia yet."* Ahmia's clearnet domain cannot currently return search
results without either executing JavaScript or going through the `.onion`
address — both excluded by the brief's own hard rules. This is a live
property of the service right now, not a markup-guessing problem a
scraper could route around. Flagged to the user; decided to skip it for
v1 rather than build something non-functional or reach for a headless
browser, which would be a much larger architectural change for one
source. No `AhmiaCollector` exists.

**Hudson Rock — the brief's own premise was checked and found wrong.**
The brief groups Hudson Rock with VirusTotal as needing a key. Checked the
real API docs (`docs.hudsonrock.com`) plus several other tools' public
integrations: the free *community* `osint-tools` endpoints this module
actually uses (`cavalier.hudsonrock.com/.../search-by-username|email|domain`)
require no key at all — only Hudson Rock's separate, paid Cavalier v3 API
does. Verified directly against the live endpoint too (a real, if slightly
alarming, infection record came back for the test username `testadmin`).
Built keyless, matching actual behavior; `HUDSONROCK_API_KEY` stays in
`.env.example` as an unused optional setting in case that ever changes.

**Ransomware.live — correct per docs, flaky in practice, live.** Fetched
the actual API documentation page served from `api.ransomware.live/apidocs`
(not a secondhand summary) to confirm the exact endpoint list and base URL
(`https://api.ransomware.live/v2`). `/v2/recentvictims` returned real data
on the first call — then 404'd on repeated isolated calls minutes later,
with `/v2/groups` and `/v2/searchvictims/<keyword>` doing the same, while
an undocumented unprefixed `/groups` happened to work. Rather than coding
against that undocumented, possibly-accidental routing, built against the
documented `/v2/` paths — the correct contract — and let the existing
cache + graceful-degradation handling absorb the live flakiness, the same
way it already absorbs crt.sh's. Reproduced again during the real CLI
run (`lantern darknet recent` logged a clean 404 and degraded instead of
crashing; a `Boeing` company search returned SEC EDGAR and GLEIF results
fine while ransomware-live silently contributed nothing for that query).

**`claim_url`** in Ransomware.live's victim records is frequently a live
`.onion` address — stored as plain text in `Finding.data`, same as Ahmia's
metadata would have been, never fetched. Consistent with the hard rule
across both darknet sources.

**Recent victims / groups aren't entity-driven.** Same reasoning as Pwned
Passwords: `/recentvictims` and `/groups` aren't triggered by a specific
`(entity_type, value)` pair, so forcing them through `Collector.collect()`
would mean inventing a query that doesn't mean anything. Exposed instead
as two small standalone functions (`fetch_recent_victims`, `fetch_groups`)
and two CLI commands, `lantern darknet recent` / `lantern darknet groups`,
outside the dispatcher entirely — the same pattern, applied a second time
now that it's clearly reusable rather than a one-off.

## 4.9 Correlator and the FastAPI SSE endpoint (Phase 5)

### The correlator's real problem, found in our own Phase 3 data

The brief's correlator rule — "common names match many people... require a
second corroborating pivot... before merging two findings into the same
Entity" — isn't hypothetical. Phase 3's live test of `lantern search
"Apple Inc"` already showed it: GLEIF's full-text search returned several
distinct "Apple"-named entities (`AM NYCF, LLC`, `Am Subr, LLC`,
`AM SUBF, LLC`, `APPLE OPERATIONS INTERNATIONAL LIMITED`, ...) alongside
SEC EDGAR's one clean `Apple Inc.` record. Naively treating "mentions
Apple" as one entity would have merged unrelated companies together.

`lantern/core/correlator.py` (`correlate()`) buckets `Finding`s by
`(entity_type, normalized value)` first — note most collectors already
report their *own* resolved value (GLEIF's `legal_name`, SEC's company
`name`), not the raw query string, so distinctly-named results land in
different buckets automatically without any extra logic. Within a bucket:
findings from a **single source** merge trivially (e.g. WhatsMyName's 78
site hits for one username — that's one collector call, definitionally
the same handle, no ambiguity). Findings from **multiple independent
sources** sharing the same value only merge when a corroborating pivot
connects them (union-find over a small, deliberately conservative set of
structured fields: GLEIF's `parent_name`, Shodan's `hostnames`,
`jurisdiction`) — otherwise each stays its own `Entity`, still returned,
just not merged. Confidence gets a small bounded boost
(`+0.05 × extra corroborating sources`, capped at 1.0) when a merge does
happen, since independent agreement is more convincing than one source
alone.

**Honest scope note**: given what our collectors currently extract, there
isn't much live material for cross-type pivoting yet (no collector pulls
an email out of a domain's WHOIS contact, for instance) — most single
searches will mostly produce one `Entity` per distinct value, which is
correct, just not very exciting to watch. The mechanism itself is
correctly built and thoroughly tested with synthetic data (11 tests
constructing the exact ambiguous-name and corroborating-pivot scenarios
directly, since relying on live data to exercise this path would be
unreliable). It gets more active as collectors extract more structured
cross-references, or if the tool later supports chaining a result back
into a new search.

`build_graph()` is a separate, smaller step: it draws **edges** between
*distinct* entities that corroborate each other (e.g. a GLEIF
subsidiary's `parent_name` matching another entity's value exactly) —
relationship, not identity. Two things can be linked in the graph without
being the same thing merged into one node. This is what satisfies
"entity graph (nodes = entities, edges = relationships)" from the brief's
output spec.

### The API

`lantern/api/app.py` — FastAPI, binds to `127.0.0.1` by default (set
explicitly in the `uvicorn.run()` call, not left to uvicorn's own
default), one endpoint: `GET /search?q=...`. Streams Server-Sent Events —
one `finding` event per `Finding` as the dispatcher produces it (so the
web UI can fill in progressively, per the design system's own
requirement), then one final `done` event carrying the correlated
`EntityGraph` (nodes + edges) as JSON.

Collectors and the `Dispatcher` are built **once**, at app startup
(FastAPI `lifespan`), not per-request — several collectors carry their own
internal rate-limiter state (§2.3) meant to track real request history
across the server's whole lifetime, not reset every request. The CLI and
API now both pull their collector list from `lantern/modules/registry.py`
(`default_collectors()`) instead of keeping two separately-maintained
lists, after noticing that was a real risk of silent drift — a new module
added to one entry point and forgotten in the other.

**Bearer token found incomplete, then fixed.** The brief says "require a
bearer token... even for local use." The first pass only protected
`/search` with it — but FastAPI auto-generates `/docs`, `/redoc`, and
`/openapi.json` unauthenticated by default, and a live check against the
running server confirmed `/docs` returned `200` with no token at all.
Read "even for local use" as applying to the whole API, not just the one
business endpoint, so those routes are disabled outright
(`docs_url=None, redoc_url=None, openapi_url=None`) rather than
individually wrapped in the auth dependency — simpler, and there's no
real need for interactive API docs on a backend whose only consumer is
our own web UI.

**Test isolation fix, not Phase-5-specific but found here.**
`get_settings()` is `@lru_cache`'d (intentional — one real settings load
per long-running process). Across a pytest session calling it from
different tests, that cache would leak the first test's env vars into
every later one. Added an autouse fixture that clears the cache before
and after every test, and also stubs out `load_dotenv()` entirely during
tests, so the suite can't accidentally pick up values from the real
developer `.env` sitting in the project root.

Live-verified against a running server (not just `TestClient`): started
the real `uvicorn` process, confirmed `GET /search` streams real Shodan
InternetDB data through to a correctly-shaped `done` event with the
entity graph, confirmed `401` with no/wrong token, and confirmed `/docs`
and `/openapi.json` both `404` post-fix.

## 4.10 Brave search and the web UI (Phase 6)

### Brave search — scoped to avoid tripling up on ambiguous queries

`lantern/modules/search/brave_search.py` is the last data source from the
brief, built last and behind a config flag as specified — it's skipped
entirely (dispatcher-level, via the `api_key_setting` mechanism already
built in Phase 1) when `BRAVE_API_KEY` isn't set.

One deliberate scoping choice: `supported_types = {PERSON, DOMAIN}`, not
also `USERNAME`/`COMPANY`. `PERSON` is produced by `classify()` but had no
collector at all until now — nothing else serves it, so Brave fills a real
gap there. `DOMAIN` is never bundled with other ambiguous types, so adding
it there doesn't duplicate anything either. `USERNAME` and `COMPANY` were
left out on purpose: both are already covered (WhatsMyName; SEC EDGAR +
GLEIF), and since an ambiguous query dispatches to every candidate type
at once, including them too would have made Brave fire three separate
times for one ambiguous search — three times the API quota burned, three
near-duplicate sets of findings, for no real benefit.

**A real bug, caught by the test suite immediately**: the first version of
`collect()` read `ctx.settings.brave_api_key` straight into a request
header with no guard. The dispatcher normally prevents this collector
from ever running without a key — but a collector shouldn't *rely* on its
caller to prevent a crash; calling it directly (as a test naturally does)
hit `TypeError: Header value must be str or bytes, not <class 'NoneType'>`
immediately. Added an explicit early return when the key is missing,
consistent with "a module that errors... must log a clear message and
return `[]` — never crash" — the dispatcher's gate is the *common* path,
not the *only* line of defense.

### Web UI

`web/` — Vite + React + TypeScript, built on the design tokens from
Phase 0 (`web/src/styles/tokens.css`), which hadn't been touched since.
Scaffolded fresh with `npm create vite@latest` rather than hand-rolled,
then the generated boilerplate (default `App.css`, sample assets,
`index.css`) was stripped back to just the tokens and one app stylesheet.

**EventSource can't carry the auth header — worked around, not around the
backend.** The API requires `Authorization: Bearer <token>` on every
request, including `/search` (§4.9). The browser's native `EventSource`
API has no mechanism to attach custom headers to its request — a
long-standing, well-known gap, not something fixable from the client
side. Rather than loosen the API's auth model (e.g. accepting the token as
a `?token=` query parameter, which would then show up in server logs and
browser history), `web/src/api.ts` implements a small hand-rolled SSE
parser over a plain authenticated `fetch()` with a streamed response body
— reads chunks, splits on blank lines, parses `event:`/`data:` pairs
manually. This keeps the backend's security model exactly as built.

**A second, small, additive backend change** for the UI's per-source
status row (design system: "a subtle per-source loading state"): added a
`sources` SSE event, emitted once up front, listing every collector name
that will run for this query (`dispatcher.applicable(classification)`,
already a public method, just not previously called from the API layer).
Deliberately *not* a deeper per-source "started"/"finished" protocol —
the `Dispatcher` has no signal for "this collector finished with zero
results" (only "produced a Finding" or "the whole stream ended"), and
building one felt like the wrong trade under time pressure: touching the
tested, working dispatcher core for a presentation-polish feature right
before a deadline. The UI approximates instead — a source's chip is
`pending` until either a `Finding` arrives (`has_results`) or the whole
stream ends (every still-`pending` chip flips to `no_results`). Accurate
in the end state, just not strictly real-time per source mid-stream.
Tested (`test_api.py`) and confirmed live against a running server.

**Entity graph shown as a list, not a node-link diagram.** The brief asks
for a graph (nodes = entities, edges = relationships) "for the web UI."
`RelationshipsList` renders the *same information* `build_graph()`
produces — which entities corroborate each other, and why — as a plain
list under a "Relationships" heading, rather than an SVG/canvas node-link
visualization. This is an honest scope call made under the deadline, not
a silent cut: the data is complete and correct (same `EntityGraph` JSON,
same edges), only the visual form is simpler. Building a real graph
layout is a reasonable next step, not a correctness gap. "Copy JSON"
(the brief's own example button copy) exposes the full underlying data
either way.

**Live-tested end to end**, not just built and assumed: ran the real
Vite dev server against the real API, searched `8.8.8.8` (single clean
finding, confirms the basic path) and `torvalds` (an ambiguous query
fanning out to six collectors at once — `brave-search`, `gleif`,
`hudson-rock`, `ransomware-live`, `sec-edgar`, `whatsmyname` — watched the
per-source chips move from pending to found/no-results in real time as
Hudson Rock's 3 results and WhatsMyName's 99 streamed in over roughly 30
seconds, matching WhatsMyName's known real-world latency from Phase 2).
Checked mobile viewport (375px) and `prefers-color-scheme: light` — both
render cleanly off the same tokens with no separate code path.

## 4.11 Post-build hardening: theme, classifier noise, and two more search sources

Work done after the initial six phases were "complete," driven by actually
using the live tool rather than new planned scope — the same pattern as
most of the real bugs caught earlier (crt.sh's 502, the SSRFError bug):
build it, run it for real, fix what the live run actually shows you.

### Green/Yellow Lantern theme

Purely cosmetic, by explicit request — swapped the single accent from
blue to a Green-Lantern green (`#15803D` light / `#22C55E` dark, with a
separate `--color-on-accent` token since a bright dark-mode green needs
near-black text, not white, to stay WCAG-AA), and gave the "no results"
source-status state its own Sinestro-yellow token rather than reusing
gray. Kept the underlying design-token architecture intact — this is a
reskin (two new semantic color tokens), not a rewrite. Also redesigned
the settings panel (it had no backdrop-click-to-close before, and could
overlap the search button when open) and added a lantern glyph as both
the favicon and the header wordmark icon.

### classify() was sending full names to the username checker

Live use (not a planned test case) surfaced this: searching a real full
name like "Mayukh Tilak" ran it through WhatsMyName as if it were a
username, and returned a page of false positives — site entries that are
themselves generic search pages, which "match" almost any input, surfaced
at a misleadingly confident 80%. Real usernames never contain whitespace,
so `classify()` now drops `USERNAME` from the ambiguous candidate set
whenever the query has a space in it, leaving `PERSON`/`COMPANY` only.
This is a correctness fix in the classifier itself, not a workaround in
WhatsMyName — it also means WhatsMyName simply never gets invoked for
multi-word queries now, which is the right outcome, not just a quieter
wrong one.

### Chasing general web search: Gemini grounding, then two keyless sources

The brief rules out designing around Google/Bing, leaving Brave as the
only in-scope general-search source — and Brave's free-tier signup asks
for a card, which the user didn't want to provide. Explored Gemini
Flash's "grounding with Google Search" tool as an alternative (confirmed
via current docs: no card needed for the base free tier, and search
grounding specifically is documented at 5,000 free grounded queries/month
with no card). Built `gemini_search.py` on the same pattern as
`brave_search.py`.

Live testing caught two real problems, in sequence:

1. **Wrong model name.** `gemini-2.5-flash` returned a `404` with an
   explicit message: *"This model ... is no longer available to new
   users ... use models/gemini-3.8-flash."* Switched to the
   `gemini-flash-latest` alias instead of a pinned version, specifically
   so this doesn't recur as models keep rotating.
2. **Grounding-specific `429 RESOURCE_EXHAUSTED`, account-level.**
   Isolated carefully rather than assumed: a plain (non-grounded)
   `generateContent` call against the same key succeeded instantly; the
   identical request with `tools: [{"google_search": {}}]` added failed
   immediately, and still failed after two separate cooldowns (25s, then
   a full 70s) — ruling out a simple per-minute burst limit. Google's own
   error text pointed at "plan and billing," meaning the documented
   no-card free tier either doesn't apply the same way to this
   account/region, or grounding specifically needs billing linked as an
   eligibility gate even within nominal free quota. This is an
   account-level condition outside this codebase's control, not a bug in
   `gemini_search.py` — confirmed by replicating the exact request
   outside the app and getting the identical error. The module is kept
   in the registry, fully built and tested, gated the same way every
   other keyed module is — it simply won't produce results until that
   account-level block is resolved or a different key is used.

Given neither Brave nor Gemini grounding was immediately usable without
either a card or resolving an account issue, added two sources that need
*neither*, ever: **Wikipedia** (`wikipedia.py`, opensearch-then-summary
against `en.wikipedia.org`) and **DuckDuckGo's Instant Answer API**
(`duckduckgo.py`). Both verified live before writing any code, same
discipline as every other source in this project. Real constraint worth
naming: DuckDuckGo's Instant Answer API is *not* a ranked web-search
results list — it's a single curated "instant answer," frequently itself
sourced from Wikipedia (confirmed live: both returned the identical
citation for a known person). Coverage is real but narrow — strong for
notable people/companies/concepts, nothing for anyone without a
reference-work presence. Both scoped to `{PERSON, DOMAIN}`, same
tripling-avoidance reasoning as `brave_search`/`gemini_search`.

**A second real bug, caught by watching the live output, not a planned
test**: DuckDuckGo and Wikipedia both returned `Linus Torvalds` citing
the *exact same URL* — but stayed as two separate, unmerged entities,
because the correlator's pivot extraction only looks inside each
`Finding.data`, and neither source populates a field `extract_pivots()`
recognized. Fixed by adding a second, independent corroboration check in
`_cluster_by_corroboration`: two findings citing an identical `url` now
merge regardless of what's in `data`. This is arguably a stronger signal
than a `data`-pivot match — it's not two sources agreeing on a shared
*fact*, it's two sources citing the literal same *page*. Added a
regression test built from the live output, same discipline as the
WhatsMyName fan-out bug back in Phase 2.

Search/general-search coverage is now four sources deep (`brave-search`,
`gemini-search`, `wikipedia`, `duckduckgo`) rather than resting on one —
directly requested after the Gemini account issue made clear that a
single general-search dependency was a real fragility, not just a
preference.

**Update, later the same day: `gemini-search` was fully removed.** After
the model-name fix (above) and the cache-on-failure fix (§4.12), the
`429 RESOURCE_EXHAUSTED` on the grounding tool persisted unchanged —
confirmed not a code issue (the exact request replicated outside the app
gave the identical error), but an account-level entitlement Google's own
error attributed to "plan and billing." Rather than keep dead, permanently
-blocked code in the registry, removed it by request: `gemini_search.py`,
its tests, the `GEMINI_API_KEY` setting, and every reference to it are
gone. Search/general-search coverage is three sources deep now
(`brave-search`, `wikipedia`, `duckduckgo`), not four. The debugging
narrative above (model deprecation, then the cache-on-failure bug it
exposed) is left as-is since both were real, instructive bugs independent
of Gemini specifically — the fixes they produced (the `gemini-flash-latest`
alias pattern, and the whole of §4.12) outlived the module itself and
apply to every other search/ collector still in the registry.

## 4.12 The cache-on-failure bug, swept across every module

The Gemini model-name fix (§4.11) exposed something bigger than itself:
fixing the model name didn't actually produce results, because the
*previous* failed attempt (the 404) had already been cached as a
legitimate empty result by `Cache.get_or_set`. Every collector's
`_fetch`-style helper followed the same shape — catch `httpx.HTTPError` /
`ValueError` internally, return `None` — and `get_or_set` has no way to
tell "the request failed" apart from "the request succeeded and
confirmed there's nothing here." Both get cached identically, for the
full TTL (up to 24h in some modules).

Once named, the fix was mechanical and the same everywhere: strip the
try/except out of each `_fetch` helper so transport errors, non-2xx
status, and JSON failures propagate as real exceptions instead of
quietly becoming `None`; catch that exception at the `get_or_set(...)`
call site instead, *outside* the cached path, so a failure is logged and
returns `[]` without ever being written to the cache. A literal `404`
stays a cacheable "confirmed not found" answer only where that's true of
the source (RDAP, SEC EDGAR, Wikipedia, Shodan, Hudson Rock) — swept
through all nine remaining collectors: `xposedornot`, `rdap`, `crtsh`,
`shodan_internetdb`, `sec_edgar`, `gleif`, `ransomware_live`,
`hudson_rock`, on top of the four search/ modules already fixed.

Two things worth calling out specifically:

**Fan-out collectors needed the catch placed carefully, not just added.**
`shodan_internetdb` (`asyncio.gather` over resolved IPs, then again over
each IP's CVEs), `sec_edgar` (`gather` over up to 5 company matches), and
`gleif` (`gather` over up to 5 records, each with its own parent lookup)
all run several of these calls concurrently. Letting the exception
propagate all the way up — rather than catching it right at each
individual item's call site — would have reintroduced the exact bug
fixed in Phase 2: one IP's, one CIK's, or one record's failure cancelling
every sibling in the same `gather()`, not just its own result.

**`ransomware_live` needed a step further, not just the same pattern.**
Already documented as observed-flaky (§4.8, §4.11) — the same path
404'ing, then succeeding moments later with no change on our end. That
means a `404` here isn't a trustworthy "confirmed not found" signal the
way it is for RDAP or SEC; it's indistinguishable from the source's own
noise. So unlike the other modules, `ransomware_live` no longer
special-cases `404` as cacheable at all — every non-2xx response is
treated as transient for this source specifically, on both the
entity-driven collector and the two standalone utility functions
(`fetch_recent_victims`, `fetch_groups`). This likely explains some of
what was previously attributed purely to "the source is flaky": once it
404'd once, our own cache was suppressing the retry that would have
shown it recovering, for up to an hour.

**Verified live, cold start, not just the test suite**: deleted the
cache file and ran a real query spanning five sources at once
(`duckduckgo`, `rdap`, `wikipedia`, `shodan-internetdb` × 2 IPs) —
clean run, no errors, same result set as before the sweep. 135 tests
still passing throughout (no new tests needed beyond the ones already
added alongside the first four fixes — this was the identical pattern
applied consistently, not new behavior to separately characterize).

## 4.13 Post-presentation-prep: SearchApi.io, a Brave pricing correction, VirusTotal, AbuseIPDB

A round of additions driven by wanting stronger, more recognizable
coverage ahead of the course presentation — plus a correction that came
out of actually double-checking assumptions this project had been
carrying since earlier phases.

**`searchapi.py`, a practical successor to the removed `gemini-search`.**
Same shape as `brave_search.py`: `{PERSON, DOMAIN}` scoping, same
cache-on-failure discipline (§4.12), gated the same way every other keyed
module is. Built against SearchApi.io's `google` engine endpoint, verified
via its live docs before writing any code (request shape: `engine=google`,
`q`, `api_key`; response: `organic_results[]` with `title`/`link`/`snippet`).
Live-tested with a real key and a real query ("Ada Lovelace") before
calling it done — 8 real results came back, matching the documented
response shape exactly.

**A pricing correction, mid-conversation.** While advising on whether to
add a second SERP-style module, asked directly whether Brave's or
SearchApi's quota "worked like credits." Rather than answer from the
comments already in this codebase (`brave_search.py` said "free tier,
2,000 queries/month" — written honestly, back when it was still true),
re-verified both against current sources first. Two things had changed
or were previously mischaracterized:

1. **Brave removed its free Search API tier in February 2026.** It's now
   metered, credit-based billing — $5 of credit granted on the 1st of
   each month (≈1,000 requests at $5/1,000), does not roll over, and
   requires a real card on file for actual billing, not just the
   identity-verification step the user had declined earlier. This is a
   materially different cost/commitment than what the existing docs
   claimed.
2. **SearchApi.io's "100 free searches" is a one-time trial pool, not a
   monthly allowance** — it never resets, unlike SerpApi's recurring
   monthly free quota. The earlier advice in this project ("~100
   searches/month") was wrong in the same direction: assumed a renewing
   quota where none exists.

Corrected everywhere the stale claims had been written: `brave_search.py`
and `wikipedia.py` docstrings, `CLAUDE.md`, `README.md`, `.env.example`.
The broader lesson, consistent with this project's existing discipline of
verifying live rather than trusting docs (§4.11's Gemini model-name bug,
the crt.sh/ransomware.live flakiness in §4.3/§4.8): a fact verified once,
at write time, isn't guaranteed to still be true months later for a
fast-moving third-party API — worth a re-check before giving advice that
depends on it, not just before writing the original integration.

**`infra/virustotal.py` and `infra/abuseipdb.py`** — named in the
project's own Known gaps list (VirusTotal, specifically called out in the
original brief) and added to strengthen IP/domain-infra coverage with
names a security audience recognizes. Both verified against current API
docs before writing code, applying the same lesson just learned from the
Brave correction above:

- **VirusTotal**: API v3, `GET /domains/{domain}` and
  `GET /ip_addresses/{ip}`, `x-apikey` header, free public tier 500
  requests/day + 4/minute. Scoped to `{IP, DOMAIN}` — both have a native
  VT endpoint, no DNS-resolve-then-fan-out needed the way
  `shodan_internetdb` needs for `DOMAIN` queries. A `404` is a genuine
  "not indexed," cacheable the same way as RDAP/SEC/Wikipedia/Shodan/Hudson
  Rock (§4.12's convention).
- **AbuseIPDB**: API v2, `GET /api/v2/check`, `Key` header, free tier
  1,000 checks/day (resets 00:00 UTC). Scoped to `{IP}` only, deliberately
  — AbuseIPDB has no native domain endpoint, and duplicating
  `shodan_internetdb`'s resolve-to-IP fan-out for one more source wasn't
  worth the added complexity for a check this narrow.

Both followed the full cache-on-failure discipline from the start (no
retrofit needed, unlike the nine modules in §4.12) since they were
written after that convention was already established. **Verified live**,
not just against the test suite: real keys, a real query against `8.8.8.8`
(Google's public DNS — a safe, well-known, non-sensitive target), both
collectors returned clean low-confidence reports as expected, confirming
the wiring end-to-end rather than resting on mocked-`respx` tests alone.

**Censys was evaluated and deliberately not built.** Its 2025 migration to
the "Censys Platform" API left the free-tier story genuinely unclear from
docs alone: community reports say free-tier Personal Access Tokens have
no organization ID and can't reach the search API, it's ambiguous whether
lookup-only endpoints (host/certificate/web-property) work without one,
and the lookup endpoints need a versioned `Accept` header
(`application/vnd.censys.api.v3.host.v1+json`) on top of the bearer
token. Building against this level of uncertainty would repeat the exact
mistake just corrected above — this one is left for whoever has an actual
Censys key to verify the current free-endpoint behavior firsthand before
the collector gets written.

Collector count: 13 → 15. Test count: 132 → 143 (11 new tests across
`test_virustotal.py` and `test_abuseipdb.py`; `test_searchapi.py` — 5
tests — had already landed earlier in this same round, bringing the
pre-VirusTotal/AbuseIPDB count from 127 to 132).

## 4.14 Removing Brave Search and DuckDuckGo

Requested outright, immediately after §4.13's additions landed: remove
both, not just stop recommending them.

**Brave Search** — the practical reason it existed at all (free general
web search) no longer held once §4.13 established its free tier is gone;
keeping a fully-built-but-unaffordable-to-activate module around added
nothing once VirusTotal and AbuseIPDB gave the project stronger,
genuinely-free coverage elsewhere. **DuckDuckGo** — never blocked on a
key, but its Instant Answer API was always narrow by design (§4.11: "a
single curated instant answer... not a ranked list of web results"), and
with SearchApi.io's real Google-results search now configured and active,
it wasn't pulling its own weight.

Removed the same way `gemini-search` was removed in §4.11 — fully, not
just unregistered:

- `lantern/modules/search/brave_search.py`, `duckduckgo.py`, and their
  test files (`tests/test_brave_search.py`, `test_duckduckgo.py`) deleted
  outright.
- Both imports and both `default_collectors()` entries removed from
  `registry.py`.
- `Settings.brave_api_key` and its `BRAVE_API_KEY` env read removed from
  `settings.py` (DuckDuckGo never had a key to remove).
- `BRAVE_API_KEY` removed from `.env.example`.
- Docstring cross-references updated rather than left dangling:
  `wikipedia.py`'s comparison-to-Brave sentence and `searchapi.py`'s
  "same reasoning as brave-search" note both rewritten to not point at
  files that no longer exist.
- `correlator.py`'s comment and `test_correlator.py`'s synthetic
  `source="duckduckgo"` Finding were left alone on purpose — they
  document/exercise the URL-pivot merge bug fixed in §4.11, using
  `"duckduckgo"` only as a literal string label in a test fixture, not an
  import of the collector. The bug and its fix are real regardless of
  whether the module still exists, same reasoning as keeping the Gemini
  debugging narrative in §4.11 after `gemini-search` itself was deleted.

**Verified clean, not just assumed**: full test suite (133 passing, down
from 143 — exactly the 10 tests removed with the two modules), a
`default_collectors()` import sanity check (13 collectors, neither name
present), and a live CLI run against `8.8.8.8` producing the same
three-finding result as before (`virustotal`, `abuseipdb`,
`shodan-internetdb` — neither removed source was ever going to fire for
an `IP` query anyway, so this mainly confirms the registry/import
surgery didn't break anything else).

Collector count: 15 → 13. Test count: 143 → 133.

## 4.15 Per-search module toggle

Requested directly: a way to pick which collectors run on a given search
— e.g. "for a hash lookup I don't want general search, just VirusTotal."
Threaded through all three entry points rather than bolted onto just the
web UI, since the underlying mechanism (restrict the dispatcher to a
named subset) is identical everywhere and the project's own convention is
CLI and API both reading from the same source of truth.

**`Dispatcher` gained one optional parameter**, not a new code path:
`applicable(classification, enabled=None)` and `stream(raw_query,
enabled=None)` both take `enabled: set[str] | None`. `None` — the
default — is byte-for-byte the previous behavior (every collector whose
`supported_types` matches); a non-`None` set additionally requires
`collector.name in enabled`. Backward compatible by construction: nothing
that already called `dispatcher.stream(query)` needed to change. Also
added `Dispatcher.collector_names`, a flat list of every registered name
regardless of entity type, for a caller that wants to offer a full toggle
list before any query has been classified.

**API**: a new `GET /sources` (bearer-protected, like every other route)
returns `{"sources": [...]}` — the same `collector_names`, sorted. `GET
/search` gained a repeatable `sources` query param
(`?sources=virustotal&sources=abuseipdb`); FastAPI collects repeats into
a `list[str] | None` automatically, converted to a `set` and passed
straight through to the dispatcher. Omitting it entirely preserves the
old unrestricted behavior — existing callers (including the CLI, which
talks to the dispatcher directly rather than through the API) don't need
to know this parameter exists.

**CLI**: `lantern search <query> --source <name>`, repeatable
(`typer.Option(None, "--source", ...)` collects into a list), converted
to the same `set[str] | None` the dispatcher expects. Verified live:
`lantern search 8.8.8.8 --source virustotal` returned exactly one
finding, from `virustotal`, where an unrestricted run returns three
(`virustotal`, `abuseipdb`, `shodan-internetdb`).

**Web UI**: the Settings panel (already holding API URL + bearer token)
gained a **Modules** section — one checkbox per collector, sourced from a
new `fetchSources()` call against `/sources` on mount and whenever the
API URL or token changes. Selection is stored as `disabledSources:
string[]` in `useSettings.ts`'s existing `localStorage`-backed settings
object — an **opt-out** list deliberately, not opt-in: a collector not
yet seen (new module added to the registry later) is absent from
`disabledSources` and therefore enabled by default, rather than silently
missing from an old saved opt-in list. At search time, `App.tsx` computes
the currently-enabled set (`availableSources` minus `disabledSources`)
and passes it to `streamSearch`, which appends it to the request as
repeated `sources=` params — but only once `availableSources` has
actually loaded; an empty not-yet-fetched list falls back to sending no
restriction at all, rather than accidentally filtering out everything.

**Verified live, full stack, not just unit tests**: started the real API
and the real Vite dev server, opened the web UI in a browser, set the
bearer token, watched the Modules checklist populate from the live
`/sources` call, manually unchecked one module via a real click (confirmed
the resulting `disabledSources` in `localStorage`), then set all-but-
`virustotal` disabled and ran `8.8.8.8` — the UI showed exactly one
source chip (`virustotal`) and the browser's network log confirmed the
actual request sent was `GET /search?q=8.8.8.8&sources=virustotal`.
Re-enabled everything and re-ran the same query: all three applicable
collectors (`virustotal`, `abuseipdb`, `shodan-internetdb`) fired, same
as before this feature existed.

New tests: `test_dispatcher.py` gained three (`enabled` restricts to the
named set, `enabled=None` is unrestricted, `collector_names` lists
everything regardless of type); `test_api.py` gained four (`/sources`
lists every registered collector, `/sources` requires a token, `/search`
with a `sources` param restricts which collectors run, `/search` without
one still runs everything). Test count: 133 → 140.

## 4.16 Full names as first-class input — name→username pivot + two native name-search collectors

Driven by a request: "if I found the full legal name of a target I should
be able to use it to the fullest, in every module." A full name already
reached the COMPANY collectors (SEC EDGAR, GLEIF) and the PERSON ones
(SearchApi, Wikipedia) because `classify()` tags a multi-word query
`PERSON+COMPANY`. The gap was the **username** side — `classify()`
deliberately withholds whitespace queries from the raw `USERNAME` path
because feeding `"john doe"` into WhatsMyName's ~600 site-checks was the
original false-positive bug (§4.11).

**We did not undo that guard.** Dumping the raw multi-word string into
site-checks was exactly the wrong move. Instead:

- **`lantern/core/names.py` — `username_variants()`**: turns `"John Doe"`
  into an ordered, deduped, ASCII/accent-normalized list of likely handles
  (`johndoe`, `john.doe`, `john_doe`, `john-doe`, `jdoe`, `johnd`,
  `doejohn`, …). A single-token input returns itself, so passing a plain
  handle through is a no-op. `limit` trims the tail for fan-out callers;
  `DEFAULT_FANOUT_VARIANTS = 5` keeps a name search from turning
  600 site-checks into thousands of requests.
- **WhatsMyName now supports `PERSON`**: on a name it expands to the capped
  variants and checks each (one shared semaphore across the whole
  handle×site fan-out, so live concurrency never exceeds the single-handle
  ceiling). Name-derived hits are scored `0.5` (vs `0.8` for a supplied
  handle) and carry `matched_handle` / `from_name` in their data.
- **Dispatcher dedup (`applicable()`)**: a collector supporting more than
  one of an ambiguous query's candidate types (the new ones support
  `USERNAME`+`PERSON`) now runs **once**, for the first supported type in
  `classification.types` order — one-word → `USERNAME`, multi-word →
  `PERSON`. Without this a name→username collector fired 2–3× on one query
  against the same value. Single-type collectors are unaffected.

**Two new keyless collectors that match names server-side** (so they don't
guess handles at all — complementary to WhatsMyName's permutation path).
Both verified live before building, per the §4.13 lesson:

- **`github_users`** (`modules/username/github_users.py`): `USERNAME` →
  `GET /users/{login}` exact lookup (404 = cacheable "no account", conf
  `0.7`); `PERSON` → `GET /search/users?q=<name>` server-side name search
  (conf `0.45`). Keyless rate limits are strict — 10 search req/min,
  60 core req/hr — so `rate_limit` is pinned to the tighter search budget
  and results cache 6h.
- **`keybase`** (`modules/username/keybase.py`): `user_search.json?q=`
  matches handles and real names the same way, serving both types. Exact
  case-insensitive handle match scores `0.7`, other handle `0.6`, name
  match `0.4`. Keybase answers `200` even on app errors (`status.code != 0`),
  so a non-zero code is raised as `ValueError` and skips the cache rather
  than poisoning it with a false empty.

**GitLab was evaluated and rejected**: its name search
(`/api/v4/users?search=`) now returns `403 Forbidden` without auth — only
exact `?username=` works keyless, which is redundant with WhatsMyName's
GitLab check. Not worth a keyed rebuild for a redundant capability.

Collector count 13 → 15. Test count 140 → 158 (`test_names.py`,
`test_github_users.py`, `test_keybase.py`, a PERSON-expansion test on
WhatsMyName, and two dispatcher dedup tests). `classify()` is unchanged —
multi-word queries stay `PERSON+COMPANY`; the username collectors reach
them via `PERSON`, not by re-adding `USERNAME` to the raw path, so the
§4.11 guard and its tests still hold.

## 4.17 Stage-1 keyless enrichment collectors + the explicit type override

Two requests, built together.

**Four new keyless collectors, each filling a gap nothing else covered.**
All verified live before building (§4.13 lesson), all keyless/no-card:

- **`dns-doh`** (DOMAIN) — live DNS over Google's DoH JSON endpoint
  (`dns.google/resolve`), A/AAAA/MX/NS/TXT. We had *registration* (RDAP)
  and *certs* (crt.sh) but no actual resolution. One request per record
  type, fanned out with `return_exceptions=True`; a partial failure keeps
  the successes, but a *total* wipeout re-raises so get_or_set doesn't cache
  a false empty. `Status != 0` (NXDOMAIN etc.) is a real empty.
- **`wayback`** (DOMAIN) — Internet Archive CDX index, first + last
  capture. CDX 504s constantly and transiently, so any non-2xx is treated
  as transient (uncached); only an empty index body is cached as "never
  archived." Two requests: `limit=1` (oldest) and `limit=-1` (newest).
- **`gravatar`** (EMAIL) — the only email→identity pivot. MD5 of the
  lowercased email → legacy `www.gravatar.com/{hash}.json` (302-redirects
  to en.gravatar.com, followed; 404 = cacheable "no profile"). Surfaces
  display name + linked social accounts. The newer `api.gravatar.com/v3`
  profile API needs OAuth, so the legacy JSON endpoint is what's keyless.
- **`ripestat`** (IP) — RIPE NCC's RIPEstat Data API: `network-info`
  (prefix + origin ASNs) then `prefix-overview` (ASN holder names).
  **This was going to be BGPView, but `api.bgpview.io` is NXDOMAIN now —
  the service is gone.** RIPEstat is the keyless, no-card, well-maintained
  replacement; `sourceapp=lantern-osint` is sent per their guidelines.

Collector count 15 → 19. A "stage 2" of keyed-but-free sources (Hunter.io,
urlscan.io, OTX) was researched and recommended but deliberately left
unbuilt pending the keys.

**Explicit type override — the input-type selector.** The brief's design is
"auto-classify, and on ambiguity run every applicable module." That's kept
as the default, but a user who *knows* the type can now skip the ambiguity
fan-out. The concern that prompted it — "does classifying add load?" — is
unfounded at the classify step (`classify()` is three regexes, microseconds,
no I/O); the real cost is the ambiguous fan-out firing person+company+
username collectors on one query. So the override is a **precision/quota**
win, not a performance one:

- `core/entities.py` → `classify_as(raw, entity_type)`: forces a single
  type, with a format check for the strict types (EMAIL/IP/DOMAIN) so
  "I picked IP but typed a name" fails fast instead of wasting a run.
  USERNAME/PERSON/COMPANY stay free-form (a name with a space is a valid
  explicit USERNAME here, unlike auto-classify's guard).
- Threaded as `Dispatcher.run/stream(..., entity_type=None)`, the API's
  `GET /search?type=`, the CLI's `--type`, and a dropdown in the web UI's
  `SearchBar` (default "Auto-detect"), carried by `api.ts`'s
  `streamSearch(..., typeOverride?)`. A bad override surfaces as the CLI's
  red error / the SSE `error` event (and the UI's existing error banner).

Verified live end-to-end: forcing `type=email` on an address ran only the
EMAIL collectors (gravatar/hudson-rock/xposedornot, with gravatar returning
a real profile) and skipped everything else; `--type ip` on a non-IP failed
with "not a valid IP address." Test count 158 → 184 (four module test
files, `classify_as` tests, and two dispatcher-override tests). `classify()`
and its tests are unchanged — the override is an alternate entry, not a
replacement.

## 5. Testing approach

- **Classifier, SSRF, rate limiter, cache, dispatcher**: tested directly,
  no network.
- **Every collector**: tested against **mocked HTTP** via `respx`, using a
  plain (unguarded) `httpx.AsyncClient` in the test `Context` fixture —
  deliberately bypassing `SSRFGuardTransport` in these tests. The SSRF
  guard is already exhaustively tested on its own (blocked/allowed ranges,
  IPv4-mapped unwrapping, scheme rejection, DNS-failure handling); re-proving
  it inside every collector test would mean every one of those tests also
  needs real DNS resolution to succeed for fictional test domains, which
  is slow, flaky, and not actually testing the collector's own logic.
- **End-to-end**: after every phase, also run for real — not just unit
  tests — against the live CLI and live third-party APIs. This is how the
  WhatsMyName fan-out bug and the crt.sh 502 were actually found; neither
  would necessarily show up in a mocked test written before the bug was
  known to exist.

Current count: **140 backend tests passing** (classifier, SSRF, rate
limiter, cache, dispatcher, WhatsMyName, XposedOrNot, RDAP, crt.sh,
Shodan infra, VirusTotal, AbuseIPDB, SEC EDGAR, GLEIF, Pwned Passwords,
Ransomware.live, Hudson Rock, SearchApi.io, Wikipedia, correlator, API —
`gemini-search` and its 8 tests were removed, see §4.11's update note;
VirusTotal/AbuseIPDB/SearchApi.io added later, see §4.13; Brave
search/DuckDuckGo and their 10 tests removed after that, see §4.14; the
module-toggle feature added 7 more across `test_dispatcher.py` and
`test_api.py`, see §4.15). The web UI has no automated test suite yet
(see §4.10) — verified by running the real stack end to end instead, same
discipline §4.15 followed for the module toggle specifically.

## 6. What's built vs. what's ahead

| Phase | Status | Contents |
|---|---|---|
| 0 | Done | Classifier, Collector/Finding contract, design tokens |
| 1 | Done | Cache, rate limiter, SSRF guard, dispatcher, settings, Entity model |
| 2 | Done | WhatsMyName, CLI wired end-to-end |
| 3 | Done | XposedOrNot, Pwned Passwords (standalone), RDAP, crt.sh, Shodan InternetDB/CVEDB, SEC EDGAR, GLEIF |
| 4 | Done | Ransomware.live, Hudson Rock (Tier-1, clearnet only). Ahmia dropped — see §4.8 |
| 5 | Done | Correlator (dedup + confidence + entity graph), FastAPI SSE endpoint — see §4.9 |
| 6 | Done | Brave search (optional, keyed), React + Vite + TS web UI — see §4.10 |
| post-build | Done | Theme, classifier fix, two keyless search sources, correlator URL-pivot fix (Gemini search built then removed, see §4.11) — see §4.11 |
| post-build | Done | Cache-on-failure bug swept across all 9 remaining modules — see §4.12 |
| post-build | Done | SearchApi.io, Brave pricing correction, VirusTotal, AbuseIPDB (Censys evaluated, deferred) — see §4.13 |
| post-build | Done | Brave Search and DuckDuckGo removed by request, fully deleted not just unregistered — see §4.14 |
| post-build | Done | Per-search module toggle — dispatcher `enabled` param, `GET /sources`, `/search?sources=`, CLI `--source`, web UI Modules checklist — see §4.15 |

## 7. Known open questions / things worth re-checking later

- WhatsMyName dataset filename (`wmn-data.json` vs. the brief's
  `wmn-dat.json`) — confirm if it ever 404s.
- The three SSRF ranges blocked beyond the brief's literal list
  (`0.0.0.0/8`, `fe80::/10`, IPv4-mapped unwrapping) — kept since they close
  obvious gaps, but flagging again here in case there's a reason to want
  the guard to match the brief exactly.
- All the undocumented rate limits/TTLs listed in §4.6 — fine as
  conservative defaults, trivial to tune once real usage patterns exist.
- Ahmia — currently unusable within this project's constraints (JS-only
  clearnet search, no Tor allowed here). Worth re-checking if Ahmia ever
  ships the no-JS version their own homepage says is still pending.
- Ransomware.live's `/v2/` routes (`recentvictims`, `groups`,
  `searchvictims`) were observed 404'ing intermittently in live testing
  even though they're the documented paths and did return real data at
  least once each. Built against the docs regardless, since that's the
  stable contract — the code already treats any failure as "no data this
  call," so nothing needs to change if/when the live backend stabilizes.
- Brave Search and DuckDuckGo are gone, not just disabled (see §4.14) —
  if either is reconsidered later, re-read §4.13/§4.14 first: Brave's
  free tier no longer exists (metered billing, real card required), and
  DuckDuckGo's Instant Answer API was always narrow by design. Neither
  concern has changed since removal.
- Censys was evaluated and deliberately not built (see §4.13) — its
  post-2025-migration free-tier access (Personal Access Tokens, lookup vs.
  search endpoint availability, the versioned `Accept` header) needs
  confirming against a real key before the collector gets written.
- The web UI's entity graph is a list, not a node-link diagram — same
  data as `EntityGraph`, simpler presentation, a reasonable next step if
  there's time before or after the presentation (see §4.10). No frontend
  test suite yet either (Vitest + Testing Library would be the natural
  choice) — the UI was verified by driving the real running app instead.
- The per-source status chips in the web UI settle to their final state
  only when the whole search completes, not the instant each individual
  source finishes (§4.10) — a deliberate scope call to avoid touching the
  tested `Dispatcher` core under deadline pressure, not a limitation of
  the underlying data.
