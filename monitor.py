

import os
import re
import sys
import json
import time
import queue
import signal
import socket
import sqlite3
import threading
from datetime import datetime
from collections import defaultdict

# Third-party
from scapy.all import sniff, DNSQR, DNS, TCP, UDP, IP, Raw, conf, get_if_list  # type: ignore
from openai import OpenAI  # official OpenAI SDK (pip install openai)

# ---------- Configuration ----------
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
IFACE = os.getenv("HOMENET_IFACE")  # optional: network interface to sniff
BPF_FILTER = os.getenv("HOMENET_BPF", "udp port 53 or tcp port 80")  # DNS + HTTP
LOG_PATH = os.getenv("HOMENET_LOG", "alerts.jsonl")
DB_PATH = os.getenv("HOMENET_DB", "verdict_cache.sqlite")
SAMPLE_RATE = float(os.getenv("HOMENET_SAMPLE_RATE", "1.0"))  # 0..1
MAX_QUEUE_SIZE = int(os.getenv("HOMENET_MAX_QUEUE", "500"))
BATCH_SIZE = int(os.getenv("HOMENET_BATCH", "8"))
QUERY_COOLDOWN_SEC = float(os.getenv("HOMENET_COOLDOWN", "0.2"))
HEURISTIC_ONLY = os.getenv("HOMENET_HEURISTIC_ONLY", "false").lower() == "true"

# ---------- Utilities ----------

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def norm_domain(d):
    d = d.strip().lower().rstrip(".")
    # strip scheme if present accidentally
    d = re.sub(r"^\w+://", "", d)
    # remove path if present
    d = d.split("/")[0]
    return d

def is_ip_literal(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False

SUSPICIOUS_TLDS = set("""zip mov cyou top kim cam xyz work country gq ga tk ml men loan mom cam salon support fit bar cricket date faith review party""".split())

def heuristic_score(indicator: dict) -> dict:
    """
    Quick local checks: structure, TLD, length, homoglyphs, IP literal, suspicious keywords.
    Returns a dict with 'risk_hint' (0-100) and reasons[]
    """
    text = indicator.get("domain") or indicator.get("url") or indicator.get("ip") or ""
    reasons = []
    score = 0

    # IP literal
    host = indicator.get("domain", "")
    if not host and indicator.get("url"):
        m = re.match(r"^\w+://([^/]+)", indicator["url"])
        if m:
            host = m.group(1)
    if not host and indicator.get("ip"):
        host = indicator["ip"]

    if host:
        host_clean = host.split(":")[0].lower()
        if is_ip_literal(host_clean):
            score += 25
            reasons.append("Uses IP literal instead of domain")

        # TLD check
        if "." in host_clean and not is_ip_literal(host_clean):
            tld = host_clean.split(".")[-1]
            if tld in SUSPICIOUS_TLDS:
                score += 15
                reasons.append(f"Uncommon/suspicious TLD: .{tld}")

        # Long subdomain or many labels
        if host_clean.count(".") >= 4 or len(host_clean) > 50:
            score += 10
            reasons.append("Very long host with many subdomains")

        # Punycode / xn--
        if "xn--" in host_clean:
            score += 15
            reasons.append("Punycode (possible homoglyph)")

        # Keyword flags
        bad_keywords = ["update", "login", "verify", "secure", "free", "bonus", "gift", "airdrop", "wallet", "support"]
        if any(k in host_clean for k in bad_keywords):
            score += 10
            reasons.append("Phishy keyword in host")

    # URL path checks
    if indicator.get("url"):
        url = indicator["url"].lower()
        if re.search(r"(?:@|%40).+@", url):
            score += 25
            reasons.append("Contains multiple '@' (credential obfuscation)")
        if re.search(r"(?:\?|&)(?:session|token|auth|key)=", url):
            score += 10
            reasons.append("Sensitive-looking query parameter")

    # Clamp
    score = max(0, min(100, score))
    return {"risk_hint": score, "reasons": reasons}

# ---------- Storage ----------

def init_db(path: str):
    con = sqlite3.connect(path)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verdicts (
            indicator TEXT PRIMARY KEY,
            kind TEXT NOT NULL,  -- domain|url|ip
            model TEXT,
            risk_score INTEGER,
            category TEXT,
            action TEXT,
            rationale TEXT,
            timestamp TEXT
        )
    """)
    con.commit()
    return con

def cache_get(con, indicator: str):
    cur = con.cursor()
    cur.execute("SELECT kind, model, risk_score, category, action, rationale, timestamp FROM verdicts WHERE indicator = ?", (indicator,))
    row = cur.fetchone()
    if not row:
        return None
    kind, model, risk, category, action, rationale, ts = row
    return {"indicator": indicator, "kind": kind, "model": model, "risk_score": risk, "category": category, "action": action, "rationale": rationale, "timestamp": ts}

def cache_put(con, v: dict):
    cur = con.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO verdicts (indicator, kind, model, risk_score, category, action, rationale, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (v["indicator"], v["kind"], v.get("model"), int(v["risk_score"]), v.get("category"), v.get("action"), v.get("rationale"), v.get("timestamp", now_iso())))
    con.commit()

# ---------- OpenAI Scoring ----------

def openai_client():
    if not OPENAI_API_KEY:
        print("[!] OPENAI_API_KEY not set. Set it in your environment or .env file.", file=sys.stderr)
        sys.exit(2)
    return OpenAI(api_key=OPENAI_API_KEY)

SYSTEM_PROMPT = """You are a cautious but not alarmist network security analyst.
Given indicators (domain, URL, or IP) from a home network:
- Estimate risk_score 0..100 (0 benign, 100 malicious/imminent harm).
- Pick category from: benign, phishing, malware, scam, tracking-ad, adult, pirated-content, command-control, crypto-scam, unknown.
- Recommend one of: allow, warn, block.
- Provide a short rationale (<= 60 words), plain and specific. Do NOT invent facts. If unsure, be conservative and label unknown with a low score.
Return ONLY compact JSON for each input item.
"""

def build_user_prompt(batch):
    items = []
    for b in batch:
        items.append({
            "kind": b["kind"],
            "value": b["value"],
            "heuristic": heuristic_score({b["kind"]: b["value"]})
        })
    return {
        "task": "Score network indicators for home safety",
        "inputs": items,
        "output_schema": {"risk_score": "int 0..100", "category": "string", "action": "allow|warn|block", "rationale": "string <= 60 words"}
    }

def call_openai(batch):
    client = openai_client()
    payload = build_user_prompt(batch)

    # Use Responses API; ask for strict JSON with one object per input in the same order
    resp = client.responses.create(
        model=OPENAI_MODEL,
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload)}
        ],
        temperature=0.2,
        max_output_tokens=400,
    )
    # Extract text
    try:
        text = resp.output_text  # modern SDK convenience
    except Exception:
        # fallback for older SDKs:
        text = getattr(resp, "content", [{}])[0].get("text", "")

    # Parse JSON robustly (allow surrounding text)
    m = re.search(r"\[.*\]|\{.*\}", text, flags=re.DOTALL)
    if not m:
        raise RuntimeError("Model did not return JSON. Raw text: " + text[:400])
    data = json.loads(m.group(0))
    # If the model returned a single object for multiple inputs, wrap logic
    if isinstance(data, dict) and "results" in data:
        results = data["results"]
    elif isinstance(data, list):
        results = data
    else:
        results = [data]

    # Normalize
    out = []
    for i, item in enumerate(results):
        try:
            out.append({
                "risk_score": int(item.get("risk_score", 0)),
                "category": str(item.get("category", "unknown")),
                "action": str(item.get("action", "warn")),
                "rationale": str(item.get("rationale", ""))[:400]
            })
        except Exception:
            out.append({
                "risk_score": 0, "category": "unknown", "action": "warn",
                "rationale": "Parse error; defaulting to conservative warn."
            })
    # Ensure length matches
    if len(out) != len(batch):
        # pad or trim
        if len(out) < len(batch):
            out += [ {"risk_score":0,"category":"unknown","action":"warn","rationale":"Missing result"} ] * (len(batch)-len(out))
        else:
            out = out[:len(batch)]
    return out

# ---------- Sniffer & Extractors ----------

def extract_indicators(pkt):
    ind = []
    ts = now_iso()

    # DNS queries
    if pkt.haslayer(DNSQR) and pkt.haslayer(UDP) and pkt[UDP].sport != 53:
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore")
        except Exception:
            qname = str(pkt[DNSQR].qname)
        domain = norm_domain(qname)
        if domain:
            ind.append(("domain", domain, ts))

    # HTTP (very simple GET/Host parser)
    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 80:
        try:
            payload = bytes(pkt[Raw].load)
            header = payload[:2048].decode(errors="ignore")
        except Exception:
            header = ""
        m1 = re.search(r"Host:\s*([^\r\n]+)", header, re.IGNORECASE)
        m2 = re.search(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+([^\s]+)", header)
        host = m1.group(1).strip() if m1 else ""
        path = m2.group(2).strip() if m2 else "/"
        if host:
            host = norm_domain(host)
            url = f"http://{host}{path}"
            ind.append(("domain", host, ts))
            ind.append(("url", url, ts))

    return ind

# ---------- Worker Threads ----------

class IndicatorQueue:
    def __init__(self, con):
        self.q = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.seen = set()
        self.con = con
        self.lock = threading.Lock()

    def put(self, kind, value, ts):
        key = f"{kind}:{value}"
        if key in self.seen:
            return
        # Check cache first
        if cache_get(self.con, value):
            self.seen.add(key)
            return
        # sampling
        import random
        if random.random() > SAMPLE_RATE:
            return
        try:
            self.q.put_nowait((kind, value, ts))
            self.seen.add(key)
        except queue.Full:
            pass

    def get_batch(self, n):
        batch = []
        while len(batch) < n:
            try:
                batch.append(self.q.get(timeout=0.2))
            except queue.Empty:
                break
        return batch

def writer(log_path):
    f = open(log_path, "a", encoding="utf-8")
    lock = threading.Lock()
    def write(event):
        with lock:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
            f.flush()
    return write

def scorer_thread(iq: IndicatorQueue, log_write):
    while True:
        batch = iq.get_batch(BATCH_SIZE)
        if not batch:
            time.sleep(0.2)
            continue
        items = [{"kind": k, "value": v, "ts": ts} for (k,v,ts) in batch]

        # Heuristic-only mode (no API calls)
        if HEURISTIC_ONLY:
            for it in items:
                h = heuristic_score({it["kind"]: it["value"]})
                verdict = {
                    "indicator": it["value"], "kind": it["kind"], "risk_score": h["risk_hint"],
                    "category": "unknown", "action": "warn",
                    "rationale": "Heuristic-only mode: " + "; ".join(h["reasons"]) if h["reasons"] else "No obvious issues."
                }
                verdict["model"] = "heuristic"
                verdict["timestamp"] = now_iso()
                cache_put(iq.con, verdict)
                log_write({"type":"verdict","ts":now_iso(),"data":verdict})
                print(f"[HEURISTIC] {it['kind']} {it['value']} -> {verdict['risk_score']}/100 {verdict['action']} ({verdict['category']}) :: {verdict['rationale']}")
            continue

        # Call OpenAI
        try:
            api_inputs = [{"kind": it["kind"], "value": it["value"]} for it in items]
            results = call_openai(api_inputs)
        except Exception as e:
            print(f"[!] OpenAI error: {e}")
            time.sleep(1.0)
            continue

        for it, res in zip(items, results):
            verdict = {
                "indicator": it["value"], "kind": it["kind"],
                "model": OPENAI_MODEL,
                "risk_score": int(res.get("risk_score", 0)),
                "category": res.get("category", "unknown"),
                "action": res.get("action", "warn"),
                "rationale": res.get("rationale", ""),
                "timestamp": now_iso()
            }
            cache_put(iq.con, verdict)
            log_write({"type":"verdict","ts":now_iso(),"data":verdict})

            # Console pretty print
            level = "OK"
            if verdict["risk_score"] >= 70 or verdict["action"] == "block":
                level = "ALERT"
            elif verdict["risk_score"] >= 40:
                level = "WARN"
            print(f"[{level}] {it['kind']} {it['value']} -> {verdict['risk_score']}/100 {verdict['action']} ({verdict['category']}) :: {verdict['rationale']}")
            time.sleep(QUERY_COOLDOWN_SEC)

def sniffer(iq: IndicatorQueue):
    def on_pkt(pkt):
        try:
            for kind, value, ts in extract_indicators(pkt):
                iq.put(kind, value, ts)
        except Exception as e:
            # ignore parse errors
            pass

    print(f"[*] Sniffing on iface={IFACE or 'auto'} with BPF='{BPF_FILTER}' ... Ctrl+C to stop")
    sniff(prn=on_pkt, store=False, filter=BPF_FILTER, iface=IFACE)

def list_interfaces():
    print("Available interfaces:")
    for i, name in enumerate(get_if_list()):
        print(f"  [{i}] {name}")

def main():
    if "--ifaces" in sys.argv:
        list_interfaces()
        sys.exit(0)

    con = init_db(DB_PATH)
    iq = IndicatorQueue(con)
    log_write = writer(LOG_PATH)

    t = threading.Thread(target=scorer_thread, args=(iq, log_write), daemon=True)
    t.start()

    # graceful shutdown
    def handle(sig, frame):
        print("\n[+] Shutting down...")
        sys.exit(0)
    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)

    sniffer(iq)

if __name__ == "__main__":
    main()
