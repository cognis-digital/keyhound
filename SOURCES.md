# Sources

## Data behind keyhound

keyhound carries two real, attributable offline datasets. No intelligence is
fabricated; every record traces to a public upstream.

### Bundled vulnerability database (`keyhound/cognis_vulndb.jsonl.gz`)

- **OSV.dev** (<https://osv.dev>) — consolidated open-source vulnerability data
  across PyPI, npm, Go, Maven, RubyGems, crates.io, and NuGet. 262,351 records
  with CVE/GHSA aliases, severity, affected packages, and dates.

### Edge data-feed catalog (`keyhound/data_feeds_2026.json`)

Real, mostly-keyless feeds fetched on demand (never automatically) and cached
for offline / air-gap use:

- **CISA KEV** — Known Exploited Vulnerabilities catalog.
- **FIRST EPSS** — Exploit Prediction Scoring System.
- **NIST NVD** — CVE API 2.0.
- **MITRE ATT&CK** — Enterprise STIX 2.1 bundle.
- **NIST SP 800-53 rev5** — OSCAL control catalog.
- **abuse.ch** — Feodo Tracker, ThreatFox, URLhaus, SSLBL.
- **OFAC SDN**, **cloud IP ranges**, **Tor exit nodes**, and more (see the
  catalog file for the full list and per-feed cadence/keyless flags).

All feeds are defensive / authorized-use intelligence only.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Conflict
- **feed** · https://www.understandingwar.org/feeds/all.xml
- **feed** · https://www.bellingcat.com/feed/
- **feed** · https://www.acleddata.com/feed/
- **feed** · https://www.aljazeera.com/xml/rss/all.xml
- **feed** · https://feeds.bbci.co.uk/news/world/rss.xml
- **live search** · `frontline situational awareness OSINT`
- **live search** · `ceasefire escalation conflict monitor`
- **live search** · `ISW Russia Ukraine assessment`
- **live search** · `Middle East conflict live updates`
- **api** · https://acleddata.com/data-export-tool/ (conflict events, free API)
- **api** · https://ucdp.uu.se/apidocs/ (UCDP georeferenced events, free)
- **api** · https://firms.modaps.eosdis.nasa.gov/api/ (NASA FIRMS fire/strike proxy, free)
- **api** · https://opensky-network.org/apidoc/ (live aircraft, free)

### Space
- **feed** · https://spacenews.com/feed/
- **feed** · https://www.nasaspaceflight.com/feed/
- **live search** · `satellite launch 2026 LEO constellation`
- **live search** · `SAR imagery commercial space`
- **api** · https://www.space-track.org (orbital catalog, free account)
- **api** · https://celestrak.org/NORAD/elements/ (TLE, free)

