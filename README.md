# MyPEN terminal web scanner

MyPEN is a defensive website security hygiene scanner. Only run active checks on systems you own or have explicit written permission to test. Add more features soon.

## Install

```bash
python -m pip install -r requirements-mypen.txt
```

Core dependencies are `requests` and `beautifulsoup4`. `reportlab` enables PDF reports, and `dnspython` enables DNS TXT/MX checks.

## Basic usage

```bash
python mypen.py https://your-domain.example --i-own-this --profile quick
python mypen.py https://your-domain.example --i-own-this --profile standard
python mypen.py https://your-domain.example --i-own-this --profile full --delay 1
```

- `quick`: skips SQL injection, reflected XSS, open redirect and port scanning; limits crawl pages.
- `standard`: runs configured checks (the default settings preserve most of the original scanner's behavior).
- `full`: explicitly enables the active checks and the optional checks.

Active tests can generate many requests. Start with `quick`, and use a conservative `--delay` on shared or production systems.

## Reports and history

```bash
python mypen.py https://your-domain.example --i-own-this --pdf mypen_report.pdf
python mypen.py --history
python mypen.py https://your-domain.example --i-own-this --baseline mypen_report.json
```

JSON and HTML reports remain enabled by default; CSV is also written by default. PDF is optional and requires `reportlab`. Scan summaries are stored in `mypen_history.sqlite3` by default. Use `--history-db PATH` to select a different SQLite database.

## Local read-only API

```bash
python mypen.py --api
```

- `GET http://127.0.0.1:8765/health`
- `GET http://127.0.0.1:8765/history`

The API is read-only and is deliberately restricted to loopback addresses. Do not expose it to a network interface.

## Safety notes

- `--i-own-this` is required for scanning and is an explicit authorization confirmation, not proof of ownership.
- Crawling is same-origin, form tests skip actions outside the exact origin, and HTTP redirects are not automatically followed by the shared request helper.
- Port scans are bounded to 4,096 ports per run and worker concurrency to 50.
- Automated SQLi/XSS/open-redirect and configuration checks are signals, not proof of exploitable vulnerabilities. Confirm findings manually.
- The local API does not trigger scans or accept scan targets; it only returns health and stored scan summaries.
