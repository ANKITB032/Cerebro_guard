"""
build_graph.py — CerebroGuard v2
Parses the Enron email dataset and saves a NetworkX graph as GraphML.

Usage:
    python3 build_graph.py --enron-path ./enron_mail_20150507 --out ./data/enron_graph.graphml

The Enron dataset can be downloaded from:
    https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz  (~1.7 GB)
"""

import os
import email
import argparse
import logging
from pathlib import Path

import networkx as nx
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VALID_EMAIL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._+-")


def is_valid_email(addr: str) -> bool:
    addr = addr.strip().lower()
    return (
        "@" in addr
        and "." in addr.split("@")[-1]
        and all(c in VALID_EMAIL_CHARS for c in addr)
        and len(addr) < 120
    )


def extract_addresses(header_value: str) -> list[str]:
    """Extract clean email addresses from a header string."""
    if not header_value:
        return []
    addresses = []
    for part in header_value.split(","):
        part = part.strip()
        # Handle "Name <email>" format
        if "<" in part and ">" in part:
            part = part[part.index("<") + 1 : part.index(">")]
        part = part.strip().lower()
        if is_valid_email(part):
            addresses.append(part)
    return addresses


def parse_email_file(path: Path) -> dict | None:
    """Parse a single email file and return sender + all recipients."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            msg = email.message_from_file(f)

        sender_raw = msg.get("From", "")
        senders = extract_addresses(sender_raw)
        if not senders:
            return None
        sender = senders[0]

        recipients = []
        for field in ("To", "CC", "Bcc"):
            recipients.extend(extract_addresses(msg.get(field, "")))

        recipients = [r for r in recipients if r != sender]

        if not recipients:
            return None

        return {"sender": sender, "recipients": recipients}

    except Exception:
        return None


def build_graph(enron_path: Path) -> nx.DiGraph:
    """Walk the Enron maildir and build a directed graph of email relationships."""
    G = nx.DiGraph()

    # Collect all email files
    all_files = list(enron_path.rglob("*"))
    email_files = [
        f for f in all_files
        if f.is_file() and not f.name.startswith(".")
    ]

    logger.info(f"Found {len(email_files):,} files to process")

    parsed = 0
    skipped = 0

    for path in tqdm(email_files, desc="Parsing emails", unit="file"):
        result = parse_email_file(path)
        if not result:
            skipped += 1
            continue

        sender = result["sender"]
        for recipient in result["recipients"]:
            if G.has_edge(sender, recipient):
                G[sender][recipient]["weight"] += 1
            else:
                G.add_edge(sender, recipient, weight=1)
        parsed += 1

    logger.info(f"Parsed: {parsed:,} | Skipped: {skipped:,}")
    logger.info(f"Graph: {G.number_of_nodes():,} nodes | {G.number_of_edges():,} edges")

    return G


def prune_graph(G: nx.DiGraph, min_weight: int = 2) -> nx.DiGraph:
    """
    Remove edges that only appear once (likely noise) and
    isolated nodes that result from pruning.
    """
    before_edges = G.number_of_edges()
    edges_to_remove = [
        (u, v) for u, v, d in G.edges(data=True)
        if d.get("weight", 1) < min_weight
    ]
    G.remove_edges_from(edges_to_remove)

    # Remove nodes with no connections after pruning
    isolated = list(nx.isolates(G))
    G.remove_nodes_from(isolated)

    logger.info(
        f"Pruned {len(edges_to_remove):,} weak edges, "
        f"{len(isolated):,} isolated nodes. "
        f"Edges: {before_edges:,} → {G.number_of_edges():,}"
    )
    return G


def main():
    parser = argparse.ArgumentParser(description="Build Enron email graph")
    parser.add_argument(
        "--enron-path",
        type=Path,
        default=Path("./enron_mail_20150507"),
        help="Path to extracted Enron dataset folder",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("./data/enron_graph.graphml"),
        help="Output path for the GraphML file",
    )
    parser.add_argument(
        "--min-weight",
        type=int,
        default=2,
        help="Minimum email count to keep an edge (default: 2)",
    )
    args = parser.parse_args()

    if not args.enron_path.exists():
        logger.error(f"Enron dataset not found at: {args.enron_path}")
        logger.error("Download it from: https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz")
        return

    logger.info(f"Building graph from: {args.enron_path}")
    G = build_graph(args.enron_path)

    logger.info(f"Pruning edges with weight < {args.min_weight}")
    G = prune_graph(G, min_weight=args.min_weight)

    # Save
    args.out.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving to {args.out} ...")
    nx.write_graphml(G, str(args.out))
    logger.info("Done! Graph saved successfully.")
    logger.info(f"Final: {G.number_of_nodes():,} nodes | {G.number_of_edges():,} edges")


if __name__ == "__main__":
    main()
