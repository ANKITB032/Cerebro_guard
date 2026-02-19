"""
CerebroGuard Phishing Analyzer v2
Dual-engine: NetworkX graph analysis + spaCy NER/NLP
"""
import re
import math
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Response schema ───────────────────────────────────────────────────────────

@dataclass
class EvidenceFactor:
    id: str
    label: str
    description: str
    severity: str          # "low" | "medium" | "high" | "critical"
    score_contribution: float


@dataclass
class AnalysisResult:
    risk_score: float                        # 0–100
    verdict: str                             # "safe" | "suspicious" | "phishing"
    confidence: float                        # 0–1
    evidence: list[EvidenceFactor] = field(default_factory=list)
    graph_stats: dict = field(default_factory=dict)
    nlp_entities: list[dict] = field(default_factory=list)

    def to_dict(self):
        return {
            "risk_score": round(self.risk_score, 1),
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "evidence": [e.__dict__ for e in self.evidence],
            "graph_stats": self.graph_stats,
            "nlp_entities": self.nlp_entities,
        }


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
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # raw IP links
    r"paypa[l1]", r"app[l1]e", r"arnazon",       # common typosquats
]


def _match_count(text: str, patterns: list[str]) -> int:
    text_lower = text.lower()
    return sum(1 for p in patterns if re.search(p, text_lower, re.IGNORECASE))


# ── Main analyzer class ───────────────────────────────────────────────────────

class PhishingAnalyzer:
    def __init__(self, graph_path: str):
        self.graph_path = graph_path
        self._graph = None
        self._nlp = None
        self._graph_lock = threading.Lock()
        self.graph_loaded = False
        self.nlp_loaded = False

        # Load both in background threads — server starts immediately
        threading.Thread(target=self._load_graph, daemon=True).start()
        threading.Thread(target=self._load_nlp, daemon=True).start()

    # ── Loaders ──────────────────────────────────────────────────────────────

    def _load_graph(self):
        try:
            import networkx as nx
            with self._graph_lock:
                self._graph = nx.read_graphml(self.graph_path)
            self.graph_loaded = True
            logger.info(f"Graph loaded: {self._graph.number_of_nodes()} nodes, "
                        f"{self._graph.number_of_edges()} edges")
        except FileNotFoundError:
            logger.warning(f"Graph file not found at {self.graph_path} — graph engine disabled")
        except Exception as e:
            logger.error(f"Graph load failed: {e}")

    def _load_nlp(self):
        try:
            import spacy
            self._nlp = spacy.load("en_core_web_sm")
            self.nlp_loaded = True
            logger.info("spaCy model loaded")
        except Exception as e:
            logger.warning(f"spaCy load failed: {e} — NLP engine disabled")

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, sender: str, recipient: str, subject: str,
                body: str, cc: list[str]) -> dict:
        full_text = f"{subject}\n{body}"
        evidence: list[EvidenceFactor] = []
        graph_stats = {}
        nlp_entities = []

        # 1. Graph analysis
        graph_result = self._analyze_graph(sender, recipient)
        evidence.extend(graph_result["factors"])
        graph_stats = graph_result["stats"]

        # 2. NLP / pattern analysis
        nlp_result = self._analyze_nlp(full_text)
        evidence.extend(nlp_result["factors"])
        nlp_entities = nlp_result["entities"]

        # 3. Header / structural checks
        evidence.extend(self._analyze_structure(sender, recipient, cc, subject))

        # 4. Score aggregation
        raw_score = sum(e.score_contribution for e in evidence)
        risk_score = min(100.0, max(0.0, raw_score))

        verdict = (
            "phishing" if risk_score >= 70
            else "suspicious" if risk_score >= 35
            else "safe"
        )

        # Confidence: higher when engines agree, lower when only one ran
        engines_active = int(self.graph_loaded) + int(self.nlp_loaded) + 1  # +1 for structure
        confidence = 0.5 + (engines_active / 3) * 0.45

        result = AnalysisResult(
            risk_score=risk_score,
            verdict=verdict,
            confidence=confidence,
            evidence=evidence,
            graph_stats=graph_stats,
            nlp_entities=nlp_entities,
        )
        return result.to_dict()

    # ── Graph engine ──────────────────────────────────────────────────────────

    def _analyze_graph(self, sender: str, recipient: str) -> dict:
        factors = []
        stats = {}

        if not self.graph_loaded or self._graph is None:
            return {"factors": factors, "stats": {"status": "unavailable"}}

        import networkx as nx
        G = self._graph

        sender_known = G.has_node(sender)
        recipient_known = G.has_node(recipient)
        has_edge = G.has_edge(sender, recipient) or G.has_edge(recipient, sender)

        stats["sender_known"] = sender_known
        stats["recipient_known"] = recipient_known
        stats["prior_contact"] = has_edge
        stats["total_nodes"] = G.number_of_nodes()

        if not sender_known:
            factors.append(EvidenceFactor(
                id="graph_unknown_sender",
                label="Unknown Sender",
                description="Sender has no history in the communication network",
                severity="high",
                score_contribution=30,
            ))
        else:
            # PageRank — high-centrality = trusted exec, low = peripheral/impersonated
            try:
                pr = nx.pagerank(G, alpha=0.85)
                sender_pr = pr.get(sender, 0)
                stats["sender_pagerank"] = round(sender_pr, 6)

                if sender_pr < 0.0001:
                    factors.append(EvidenceFactor(
                        id="graph_low_centrality",
                        label="Low Network Centrality",
                        description=f"Sender is peripheral in the network (PageRank: {sender_pr:.5f})",
                        severity="medium",
                        score_contribution=20,
                    ))
                else:
                    factors.append(EvidenceFactor(
                        id="graph_trusted_sender",
                        label="Established Network Node",
                        description=f"Sender is a known, connected participant (PageRank: {sender_pr:.5f})",
                        severity="low",
                        score_contribution=-15,
                    ))

                # Degree centrality
                deg = G.degree(sender)
                stats["sender_degree"] = deg
                if deg < 3:
                    factors.append(EvidenceFactor(
                        id="graph_low_degree",
                        label="Few Connections",
                        description=f"Sender has only {deg} connections — unusual for a legitimate address",
                        severity="medium",
                        score_contribution=15,
                    ))

            except Exception as e:
                logger.warning(f"PageRank calculation failed: {e}")

        if not has_edge:
            factors.append(EvidenceFactor(
                id="graph_no_prior_contact",
                label="No Prior Contact",
                description="No previous communication between sender and recipient",
                severity="medium",
                score_contribution=20,
            ))
        else:
            factors.append(EvidenceFactor(
                id="graph_prior_contact",
                label="Prior Communication Found",
                description="Sender and recipient have communicated before",
                severity="low",
                score_contribution=-10,
            ))

        return {"factors": factors, "stats": stats}

    # ── NLP engine ────────────────────────────────────────────────────────────

    def _analyze_nlp(self, text: str) -> dict:
        factors = []
        entities = []

        # Pattern matching (always runs)
        urgency_hits = _match_count(text, URGENCY_PATTERNS)
        money_hits = _match_count(text, MONEY_PATTERNS)
        cred_hits = _match_count(text, CREDENTIAL_PATTERNS)
        social_hits = _match_count(text, SOCIAL_ENG_PATTERNS)
        domain_hits = _match_count(text, SUSPICIOUS_DOMAINS)

        if urgency_hits:
            factors.append(EvidenceFactor(
                id="nlp_urgency",
                label="Urgency Language",
                description=f"Detected {urgency_hits} urgency indicator(s) — common pressure tactic",
                severity="high" if urgency_hits >= 3 else "medium",
                score_contribution=min(25, urgency_hits * 7),
            ))

        if money_hits:
            factors.append(EvidenceFactor(
                id="nlp_money",
                label="Financial References",
                description=f"Found {money_hits} financial indicator(s): amounts, wire transfers, or crypto",
                severity="high" if money_hits >= 3 else "medium",
                score_contribution=min(20, money_hits * 5),
            ))

        if cred_hits:
            factors.append(EvidenceFactor(
                id="nlp_credentials",
                label="Credential Harvesting Language",
                description=f"Detected {cred_hits} credential-seeking phrase(s)",
                severity="critical",
                score_contribution=min(30, cred_hits * 10),
            ))

        if social_hits:
            factors.append(EvidenceFactor(
                id="nlp_social_engineering",
                label="Social Engineering Tactics",
                description="Detected secrecy or authority impersonation language",
                severity="high",
                score_contribution=min(25, social_hits * 12),
            ))

        if domain_hits:
            factors.append(EvidenceFactor(
                id="nlp_suspicious_urls",
                label="Suspicious URLs",
                description=f"Found {domain_hits} suspicious link(s): shortened URLs or IP addresses",
                severity="critical",
                score_contribution=min(35, domain_hits * 15),
            ))

        # spaCy NER (runs if model loaded)
        if self.nlp_loaded and self._nlp:
            try:
                doc = self._nlp(text[:10_000])  # cap for performance
                for ent in doc.ents:
                    if ent.label_ in ("MONEY", "ORG", "PERSON", "GPE", "DATE"):
                        entities.append({
                            "text": ent.text,
                            "label": ent.label_,
                            "start": ent.start_char,
                            "end": ent.end_char,
                        })

                money_ents = [e for e in entities if e["label"] == "MONEY"]
                if money_ents:
                    factors.append(EvidenceFactor(
                        id="nlp_ner_money",
                        label="NER: Monetary Entities",
                        description=f"spaCy identified {len(money_ents)} monetary reference(s) in body",
                        severity="medium",
                        score_contribution=len(money_ents) * 4,
                    ))
            except Exception as e:
                logger.warning(f"spaCy NER failed: {e}")

        return {"factors": factors, "entities": entities}

    # ── Structural checks ─────────────────────────────────────────────────────

    def _analyze_structure(self, sender: str, recipient: str,
                           cc: list[str], subject: str) -> list[EvidenceFactor]:
        factors = []

        # Sender domain check
        if "@" in sender:
            domain = sender.split("@")[-1].lower()
            free_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}
            if domain in free_domains:
                factors.append(EvidenceFactor(
                    id="struct_free_email",
                    label="Free Email Provider",
                    description=f"Sender uses {domain} — uncommon for business communications",
                    severity="low",
                    score_contribution=8,
                ))

            # Domain mismatch between sender and recipient
            if "@" in recipient:
                rec_domain = recipient.split("@")[-1].lower()
                if domain != rec_domain and rec_domain not in free_domains:
                    factors.append(EvidenceFactor(
                        id="struct_domain_mismatch",
                        label="Cross-Domain Communication",
                        description="Sender and recipient are on different domains",
                        severity="low",
                        score_contribution=5,
                    ))

        # Subject line checks
        subj_lower = subject.lower()
        if re.search(r"re:\s*re:|fwd:\s*fwd:", subj_lower):
            factors.append(EvidenceFactor(
                id="struct_reply_chain_spoof",
                label="Reply Chain Spoofing",
                description="Suspicious repeated Re:/Fwd: prefixes — possible thread hijacking",
                severity="medium",
                score_contribution=15,
            ))

        if not subject.strip():
            factors.append(EvidenceFactor(
                id="struct_no_subject",
                label="Empty Subject Line",
                description="No subject line — unusual for legitimate communication",
                severity="low",
                score_contribution=5,
            ))

        # Excessive CC recipients
        if len(cc) > 10:
            factors.append(EvidenceFactor(
                id="struct_mass_cc",
                label="Mass CC List",
                description=f"Email CC'd to {len(cc)} recipients — possible spam/phishing blast",
                severity="medium",
                score_contribution=12,
            ))

        return factors
