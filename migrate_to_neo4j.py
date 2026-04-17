"""
migrate_to_neo4j.py — CerebroGuard v2
Loads the Enron GraphML file and pushes it into Neo4j Aura.

Usage:
    python3 migrate_to_neo4j.py

Set your credentials in the three variables below before running.
"""

import os
import networkx as nx
from neo4j import GraphDatabase
from tqdm import tqdm

# ── Set your credentials here ─────────────────────────────────────────────────
NEO4J_URI      = "neo4j+s://aa4e8753.databases.neo4j.io"   # replace
NEO4J_USERNAME = "aa4e8753"                                    # usually neo4j
NEO4J_PASSWORD = "vZCQZLZXhcahvVZdwqr3QPEUPY4TzdJl4zD2Owmj-us"                       # replace
GRAPH_PATH     = "./data/enron_graph.graphml"
# ─────────────────────────────────────────────────────────────────────────────

BATCH_SIZE = 500  # upload 500 edges at a time


def upload_batch(tx, batch):
    tx.run("""
        UNWIND $rows AS row
        MERGE (a:Person {email: row.sender})
        MERGE (b:Person {email: row.recipient})
        MERGE (a)-[r:EMAILED]->(b)
        ON CREATE SET r.weight = row.weight
        ON MATCH  SET r.weight = r.weight + row.weight
    """, rows=batch)


def main():
    print(f"Loading graph from {GRAPH_PATH} ...")
    G = nx.read_graphml(GRAPH_PATH)
    print(f"Graph loaded: {G.number_of_nodes():,} nodes, {G.number_of_edges():,} edges")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

    # Test connection
    with driver.session() as session:
        result = session.run("RETURN 1 AS ok")
        print("Neo4j connection successful ✓")

    # Build edge list
    edges = [
        {
            "sender":    u,
            "recipient": v,
            "weight":    d.get("weight", 1),
        }
        for u, v, d in G.edges(data=True)
    ]

    # Upload in batches
    print(f"Uploading {len(edges):,} edges in batches of {BATCH_SIZE} ...")
    with driver.session() as session:
        for i in tqdm(range(0, len(edges), BATCH_SIZE), unit="batch"):
            batch = edges[i : i + BATCH_SIZE]
            session.execute_write(upload_batch, batch)

    # Create index for fast lookup
    print("Creating indexes ...")
    with driver.session() as session:
        session.run("CREATE INDEX person_email IF NOT EXISTS FOR (p:Person) ON (p.email)")

    driver.close()
    print("Migration complete! ✓")
    print(f"Uploaded {len(edges):,} edges to Neo4j Aura.")


if __name__ == "__main__":
    main()
