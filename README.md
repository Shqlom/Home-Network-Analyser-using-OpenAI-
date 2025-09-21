# HomeNet Guardian

A tiny, privacy-conscious home network watcher that inspects DNS queries and any plain HTTP requests from your LAN, then asks the OpenAI (ChatGPT) API to score domains/URLs/IPs for risk. You get console alerts and a JSONL log, plus a local cache so you don't re-score the same indicators.

> **No decryption.** HTTPS payloads remain private; the tool mostly uses DNS hosts (and any HTTP traffic if present).

## Features
- Live sniffing of DNS and HTTP (port 80)
- Fast local heuristics to catch obvious red flags
- OpenAI Responses API scoring with short explanations
- SQLite cache of verdicts
- JSONL alert log
- Heuristic-only mode (no API calls)

## Install
```bash
# macOS / Linux
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Windows
py -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
```

## Configure
Create a `.env` file in this folder:
```
OPENAI_API_KEY=sk-...
# Optional overrides
OPENAI_MODEL=gpt-5
HOMENET_IFACE=              # e.g., en0 (mac), eth0 (linux), Ethernet or Wi-Fi (win)
HOMENET_BPF=udp port 53 or tcp port 80
HOMENET_SAMPLE_RATE=1.0
HOMENET_HEURISTIC_ONLY=false
```

Load the `.env` (optional) before running:
```bash
# macOS/Linux
export $(grep -v '^#' .env | xargs -I{} echo {})
# Windows PowerShell
Get-Content .env | foreach { if ($_ -and $_ -notmatch '^#') { $n,$v = $_.split('='); [Environment]::SetEnvironmentVariable($n,$v) } }
```

## Run
List interfaces:
```bash
sudo python monitor.py --ifaces
```
Start monitoring (sudo/admin required to sniff):
```bash
sudo python monitor.py
# or pick interface
sudo HOMENET_IFACE=en0 python monitor.py
```

Logs are written to `alerts.jsonl` and verdicts cached in `verdict_cache.sqlite`.

## How it judges risk
1. **Heuristics:** checks IP literals, odd TLDs, punycode, long subdomains, phishy keywords, etc.
2. **OpenAI model:** the indicator + heuristic hints are sent to the OpenAI **Responses API** (`model=OPENAI_MODEL`) asking for a compact JSON verdict with fields:
   - `risk_score` (0–100)
   - `category` (benign/phishing/malware/…)
   - `action` (allow/warn/block)
   - `rationale` (≤60 words)

If you want zero cloud calls, set `HOMENET_HEURISTIC_ONLY=true`.

## Safety & Privacy
- Only metadata (domains/URLs/IPs) are scored.
- Respect local laws and ISP policies.
- Run only on networks you own or have permission to monitor.

## Troubleshooting
- **Permission errors:** run with sudo/admin; packet capture requires elevated privileges.
- **Windows capture issues:** try running PowerShell as Administrator and ensure WinPcap/Npcap is installed.
- **No results on HTTPS-only networks:** that's expected; rely on DNS indicators.
- **API errors/rate limits:** the tool backs off between calls. Reduce `HOMENET_SAMPLE_RATE` or increase `HOMENET_COOLDOWN`.

## Roadmap ideas
- Optional PyShark backend to parse TLS SNI
- Simple web dashboard (Flask) over the SQLite cache
- Enrich with public threat intel APIs (AbuseIPDB, OTX) before LLM scoring
