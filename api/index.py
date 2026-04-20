"""
api/index.py — CerebroGuard v2 (Vercel Serverless - Lightweight)
Queries Neo4j Aura for graph intelligence + regex NLP (spaCy removed for Vercel limits)
"""
import re
import os
import json
import logging
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler

from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Neo4j connection ──────────────────────────────────────────────────────────
NEO4J_URI      = os.environ.get("NEO4J_URI", "")
NEO4J_USERNAME = os.environ.get("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

# ── Google OAuth Constants ────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = "https://cerebro-guard.vercel.app/api/callback"
GMAIL_SCOPES         = "https://www.googleapis.com/auth/gmail.readonly"

_driver = None

def get_driver():
    global _driver
    if _driver is None and NEO4J_URI:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    return _driver


# ── OAuth & Gmail Helper Functions ────────────────────────────────────────────
def build_auth_url():
    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         GMAIL_SCOPES,
        "access_type":   "offline",   
        "prompt":        "consent",   
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


def exchange_code_for_tokens(code):
    payload = urllib.parse.urlencode({
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code",
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def store_token_in_neo4j(token_data):
    driver = get_driver()
    if not driver:
        raise RuntimeError("Neo4j unavailable")
    with driver.session() as session:
        session.run("""
            MERGE (t:GmailToken {id: 'primary'})
            SET t.access_token  = $access_token,
                t.refresh_token = $refresh_token,
                t.expires_in    = $expires_in,
                t.scope         = $scope,
                t.token_type    = $token_type,
                t.stored_at     = timestamp()
        """,
            access_token  = token_data.get("access_token", ""),
            refresh_token = token_data.get("refresh_token", ""),
            expires_in    = token_data.get("expires_in", 3600),
            scope         = token_data.get("scope", ""),
            token_type    = token_data.get("token_type", "Bearer"),
        )


def get_valid_token():
    driver = get_driver()
    if not driver:
        raise RuntimeError("Neo4j unavailable")

    with driver.session() as session:
        row = session.run("""
            MATCH (t:GmailToken {id: 'primary'})
            RETURN t.access_token  AS access_token,
                   t.refresh_token AS refresh_token,
                   t.expires_in    AS expires_in,
                   t.stored_at     AS stored_at
        """).single()

    if not row:
        raise RuntimeError("No GmailToken found — connect Gmail first")

    stored_at_ms = row["stored_at"]
    expires_in   = row["expires_in"] or 3600
    age_seconds  = (time.time() * 1000 - stored_at_ms) / 1000

    if age_seconds < (expires_in - 300):
        return row["access_token"]

    logger.info("Access token stale — refreshing")
    payload = urllib.parse.urlencode({
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "refresh_token": row["refresh_token"],
        "grant_type":    "refresh_token",
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        new_token = json.loads(resp.read())

    with driver.session() as session:
        session.run("""
            MATCH (t:GmailToken {id: 'primary'})
            SET t.access_token = $access_token,
                t.expires_in   = $expires_in,
                t.stored_at    = timestamp()
        """,
            access_token = new_token["access_token"],
            expires_in   = new_token.get("expires_in", 3600),
        )

    return new_token["access_token"]


def fetch_recent_emails(max_results=50):
    token   = get_valid_token()
    headers = {"Authorization": f"Bearer {token}"}

    list_url = (
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?"
        + urllib.parse.urlencode({"maxResults": max_results, "fields": "messages/id"})
    )
    req = urllib.request.Request(list_url, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        msg_ids = [m["id"] for m in json.loads(resp.read()).get("messages", [])]

    emails = []
    for msg_id in msg_ids:
        detail_url = (
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?"
            + urllib.parse.urlencode({
                "format": "metadata",
                "metadataHeaders": ["From", "To"],
                "fields": "payload/headers",
            }, doseq=True)
        )
        try:
            req = urllib.request.Request(detail_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                hdrs = json.loads(resp.read()).get("payload", {}).get("headers", [])
            hdr_map = {h["name"].lower(): h["value"] for h in hdrs}
            sender    = _extract_email(hdr_map.get("from", ""))
            recipient = _extract_email(hdr_map.get("to", ""))
            if sender and recipient:
                emails.append({"sender": sender, "recipient": recipient})
        except Exception as e:
            logger.warning(f"Skipping message {msg_id}: {e}")

    return emails


def _extract_email(raw):
    m = re.search(r"<([^>]+)>", raw)
    addr = m.group(1) if m else raw.strip()
    return addr.lower() if "@" in addr else ""


def update_personal_graph(emails):
    driver = get_driver()
    if not driver:
        raise RuntimeError("Neo4j unavailable")

    from collections import Counter
    pair_counts = Counter((e["sender"], e["recipient"]) for e in emails)

    with driver.session() as session:
        for (sender, recipient), count in pair_counts.items():
            session.run("""
                MERGE (s:Person {email: $sender})
                MERGE (r:Person {email: $recipient})
                MERGE (s)-[rel:EMAILED]->(r)
                  ON CREATE SET rel.weight = $count
                  ON MATCH  SET rel.weight = rel.weight + $count
            """, sender=sender, recipient=recipient, count=count)

    return {"pairs_merged": len(pair_counts), "emails_processed": len(emails)}


# ── Threat patterns ───────────────────────────────────────────────────────────
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bASAP\b", r"\bdeadline\b",
    r"\bexpires?\b", r"\bact now\b", r"\btime.sensitive\b", r"\bwithin \d+ hours?\b",
]
MONEY_PATTERNS = [
    r"\$[\d,]+", r"\b\d+[kKmM]\b", r"\b\d{1,3}(?:,\d{3})+\b",
    r"\bwire transfer\b", r"\bdirect deposit\b", r"\bgift card\b",
    r"\bcrypto\b", r"\bbitcoin\b",
]
CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bcredential\b", r"\bverify your account\b",
    r"\bclick here\b", r"\bconfirm your\b", r"\bsign in\b", r"\blog.?in\b",
]
SOCIAL_ENG_PATTERNS = [
    r"\bconfidential\b", r"\bdo not (share|forward|tell)\b",
    r"\bbetween (us|you and me)\b", r"\bkeep this (quiet|secret|private)\b",
    r"\bceo\b.{0,40}\b(request|ask|need)\b",
    r"\b(request|ask|need)\b.{0,40}\bceo\b",
]
SUSPICIOUS_DOMAINS = [
    r"bit\.ly", r"tinyurl", r"t\.co\/", r"ow\.ly",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"paypa[l1]", r"app[l1]e", r"arnazon",
]

def match_count(text, patterns):
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))


# ── Graph analysis via Neo4j ──────────────────────────────────────────────────
def analyze_graph(sender, recipient):
    factors = []
    stats   = {}
    driver  = get_driver()

    if not driver:
        return {"factors": factors, "stats": {"status": "unavailable"}}

    try:
        with driver.session() as session:
            sender_result = session.run("""
                OPTIONAL MATCH (s:Person {email: $email})
                RETURN s IS NOT NULL AS exists,
                       CASE WHEN s IS NOT NULL
                            THEN size([(s)-[:EMAILED]->() | 1]) + size([()-[:EMAILED]->(s) | 1])
                            ELSE 0 END AS degree
            """, email=sender).single()

            sender_known  = sender_result["exists"]
            sender_degree = sender_result["degree"]

            recip_result = session.run("""
                OPTIONAL MATCH (r:Person {email: $email})
                RETURN r IS NOT NULL AS exists
            """, email=recipient).single()
            recipient_known = recip_result["exists"]

            contact_result = session.run("""
                OPTIONAL MATCH (s:Person {email: $sender})-[r:EMAILED]->(t:Person {email: $recipient})
                OPTIONAL MATCH (t2:Person {email: $recipient})-[r2:EMAILED]->(s2:Person {email: $sender})
                RETURN (r IS NOT NULL OR r2 IS NOT NULL) AS has_contact,
                       COALESCE(r.weight, 0) + COALESCE(r2.weight, 0) AS total_weight
            """, sender=sender, recipient=recipient).single()

            has_contact  = contact_result["has_contact"]
            email_weight = contact_result["total_weight"]

            count_result = session.run("MATCH (p:Person) RETURN count(p) AS total").single()
            total_nodes  = count_result["total"]

        stats = {
            "sender_known":    sender_known,
            "recipient_known": recipient_known,
            "prior_contact":   has_contact,
            "sender_degree":   sender_degree,
            "email_weight":    email_weight,
            "total_nodes":     total_nodes,
        }

        if not sender_known:
            factors.append({
                "id": "graph_unknown_sender", "label": "Unknown Sender",
                "description": "Sender has no history in the Enron communication network",
                "severity": "high", "score_contribution": 30,
            })
        else:
            if sender_degree < 3:
                factors.append({
                    "id": "graph_low_degree", "label": "Few Network Connections",
                    "description": f"Sender has only {sender_degree} connections — unusual for a legitimate address",
                    "severity": "medium", "score_contribution": 20,
                })
            else:
                factors.append({
                    "id": "graph_trusted_sender", "label": "Established Network Node",
                    "description": f"Sender has {sender_degree} known connections in the network",
                    "severity": "low", "score_contribution": -15,
                })

        if not has_contact:
            factors.append({
                "id": "graph_no_prior_contact", "label": "No Prior Contact",
                "description": "No previous communication between sender and recipient",
                "severity": "medium", "score_contribution": 20,
            })
        else:
            factors.append({
                "id": "graph_prior_contact", "label": "Prior Communication Found",
                "description": f"Sender and recipient have exchanged {email_weight} email(s) before",
                "severity": "low", "score_contribution": -10,
            })

    except Exception as e:
        logger.error(f"Neo4j query failed: {e}")
        stats = {"status": "error"}

    return {"factors": factors, "stats": stats}


# ── NLP analysis ──────────────────────────────────────────────────────────────
def analyze_nlp(text):
    factors  = []
    entities = [] 

    urgency_hits = match_count(text, URGENCY_PATTERNS)
    money_hits   = match_count(text, MONEY_PATTERNS)
    cred_hits    = match_count(text, CREDENTIAL_PATTERNS)
    social_hits  = match_count(text, SOCIAL_ENG_PATTERNS)
    domain_hits  = match_count(text, SUSPICIOUS_DOMAINS)

    if urgency_hits:
        factors.append({
            "id": "nlp_urgency", "label": "Urgency Language",
            "description": f"Detected {urgency_hits} urgency indicator(s) — common pressure tactic",
            "severity": "high" if urgency_hits >= 3 else "medium", "score_contribution": min(25, urgency_hits * 7),
        })
    if money_hits:
        factors.append({
            "id": "nlp_money", "label": "Financial References",
            "description": f"Found {money_hits} financial indicator(s): amounts, wire transfers, or crypto",
            "severity": "high" if money_hits >= 3 else "medium", "score_contribution": min(20, money_hits * 5),
        })
    if cred_hits:
        factors.append({
            "id": "nlp_credentials", "label": "Credential Harvesting Language",
            "description": f"Detected {cred_hits} credential-seeking phrase(s)",
            "severity": "critical", "score_contribution": min(30, cred_hits * 10),
        })
    if social_hits:
        factors.append({
            "id": "nlp_social_engineering", "label": "Social Engineering Tactics",
            "description": "Detected secrecy or authority impersonation language",
            "severity": "high", "score_contribution": min(25, social_hits * 12),
        })
    if domain_hits:
        factors.append({
            "id": "nlp_suspicious_urls", "label": "Suspicious URLs",
            "description": f"Found {domain_hits} suspicious link(s): shortened URLs or raw IPs",
            "severity": "critical", "score_contribution": min(35, domain_hits * 15),
        })

    return {"factors": factors, "entities": entities}


# ── Structural checks ─────────────────────────────────────────────────────────
def analyze_structure(sender, recipient, cc, subject):
    factors = []

    if "@" in sender:
        domain = sender.split("@")[-1].lower()
        free   = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}
        if domain in free:
            factors.append({
                "id": "struct_free_email", "label": "Free Email Provider",
                "description": f"Sender uses {domain} — uncommon for business communications",
                "severity": "low", "score_contribution": 8,
            })
        if "@" in recipient:
            rec_domain = recipient.split("@")[-1].lower()
            if domain != rec_domain and rec_domain not in free:
                factors.append({
                    "id": "struct_domain_mismatch", "label": "Cross-Domain Communication",
                    "description": "Sender and recipient are on different domains",
                    "severity": "low", "score_contribution": 5,
                })

    if re.search(r"re:\s*re:|fwd:\s*fwd:", subject, re.IGNORECASE):
        factors.append({
            "id": "struct_reply_chain_spoof", "label": "Reply Chain Spoofing",
            "description": "Suspicious repeated Re:/Fwd: prefixes — possible thread hijacking",
            "severity": "medium", "score_contribution": 15,
        })

    if not subject.strip():
        factors.append({
            "id": "struct_no_subject", "label": "Empty Subject Line",
            "description": "No subject — unusual for legitimate communication",
            "severity": "low", "score_contribution": 5,
        })

    return factors


# ── Vercel handler ────────────────────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        # ── /api/connect → redirect to Google consent screen ─────────────────
        if path == "/api/connect":
            url = build_auth_url()
            self.send_response(302)
            self._cors()
            self.send_header("Location", url)
            self.end_headers()
            return
        
        # ── /api/sync-graph → fetch Gmail headers + rebuild personal graph ────
        if path == "/api/sync-graph":
            try:
                emails = fetch_recent_emails(max_results=50)
                stats  = update_personal_graph(emails)
                self._respond(200, {"status": "ok", **stats})
            except Exception as e:
                logger.error(f"Graph sync error: {e}")
                self._respond(500, {"error": str(e)})
            return

        # ── /api/callback → exchange code, store token, show result page ──────
        if path == "/api/callback":
            code  = qs.get("code",  [None])[0]
            error = qs.get("error", [None])[0]

            if error or not code:
                self._html_response(400, f"<h2>OAuth Error</h2><pre>{error or 'no code returned'}</pre>")
                return

            try:
                token_data = exchange_code_for_tokens(code)
                store_token_in_neo4j(token_data)
                self._html_response(200, """
                    <h2 style='color:#00e676;font-family:monospace'>✓ Gmail Connected</h2>
                    <p style='font-family:monospace;color:#cdd9e5'>
                        Access token stored in Neo4j.<br>
                        Refresh token secured. You can close this tab.
                    </p>
                """)
            except Exception as e:
                logger.error(f"OAuth callback error: {e}")
                self._html_response(500, f"<h2>Token Exchange Failed</h2><pre>{e}</pre>")
            return

        # ── /api/keep-alive → prevent Neo4j from pausing ──────────────────────
        if path == "/api/keep-alive":
            driver = get_driver()
            if driver:
                with driver.session() as session:
                    session.run("MERGE (k:KeepAlive {id: 'ping'}) SET k.lastPing = timestamp()")
                self._html_response(200, "<p>Database pinged successfully.</p>")
            return

        # ── default → serve index.html ────────────────────────────────────────
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        try:
            html_paths = ["index.html", "public/index.html", "../index.html"]
            html_content = b"<h1>CerebroGuard API Active</h1><p>UI file not found.</p>"
            for p in html_paths:
                if os.path.exists(p):
                    with open(p, "rb") as f:
                        html_content = f.read()
                    break
            self.wfile.write(html_content)
        except Exception:
            self.wfile.write(b"<h1>CerebroGuard API Active</h1>")

    def do_POST(self):
        try:
            length  = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))

            sender    = payload.get("sender", "").strip()
            recipient = payload.get("recipient", "").strip()
            subject   = payload.get("subject", "")
            body      = payload.get("body", "")[:20_000]
            cc        = payload.get("cc", [])

            if not sender or not recipient:
                self._respond(400, {"error": "sender and recipient are required"})
                return

            full_text    = f"{subject}\n{body}"
            graph_result = analyze_graph(sender, recipient)
            nlp_result   = analyze_nlp(full_text)
            struct       = analyze_structure(sender, recipient, cc, subject)

            evidence  = graph_result["factors"] + nlp_result["factors"] + struct
            raw_score = sum(e["score_contribution"] for e in evidence)
            risk_score = min(100.0, max(0.0, raw_score))

            verdict = (
                "phishing"   if risk_score >= 70 else
                "suspicious" if risk_score >= 35 else
                "safe"
            )

            graph_ok = graph_result["stats"].get("status") not in ("unavailable", "error")
            engines  = int(graph_ok) + 2 
            confidence = round(0.5 + (engines / 3) * 0.45, 3)

            self._respond(200, {
                "risk_score":   round(risk_score, 1),
                "verdict":      verdict,
                "confidence":   confidence,
                "evidence":     evidence,
                "graph_stats":  graph_result["stats"],
                "nlp_entities": nlp_result["entities"],
            })

        except Exception as e:
            logger.error(f"Handler error: {e}")
            self._respond(500, {"error": "Analysis failed"})

    def _respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _html_response(self, status, body_html):
        page = f"""<!DOCTYPE html><html><head>
        <meta charset='UTF-8'/>
        <style>body{{background:#060a0f;color:#cdd9e5;font-family:monospace;
        display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
        div{{max-width:480px;padding:32px;border:1px solid #1a2a3a;}}</style>
        </head><body><div>{body_html}</div></body></html>""".encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(page))
        self.end_headers()
        self.wfile.write(page)