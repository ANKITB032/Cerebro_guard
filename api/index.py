"""
api/index.py — CerebroGuard v2 (Vercel Serverless - Lightweight)
Queries Neo4j Aura for graph intelligence + regex NLP (spaCy removed for Vercel limits)
"""
import re
import os
import json
import logging
from http.server import BaseHTTPRequestHandler

from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Neo4j connection ──────────────────────────────────────────────────────────
NEO4J_URI      = os.environ.get("NEO4J_URI", "")
NEO4J_USERNAME = os.environ.get("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")

_driver = None

def get_driver():
    global _driver
    if _driver is None and NEO4J_URI:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    return _driver


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
    entities = [] # Keeping empty to prevent frontend crashes

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

    if len(cc) > 10:
        factors.append({
            "id": "struct_mass_cc", "label": "Mass CC List",
            "description": f"Email CC'd to {len(cc)} recipients — possible phishing blast",
            "severity": "medium", "score_contribution": 12,
        })

    return factors


# ── Vercel handler ────────────────────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        try:
            # Bulletproof pathfinding: searches root, public, and parent directories
            html_paths = ["index.html", "public/index.html", "../index.html"]
            html_content = b"<h1>CerebroGuard API Active</h1><p>UI file not found.</p>"
            for path in html_paths:
                if os.path.exists(path):
                    with open(path, "rb") as f:
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
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")