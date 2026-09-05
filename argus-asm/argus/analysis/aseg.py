"""Attack Surface Evolution Graph (ASEG).

Builds a NetworkX graph from a recon result and computes the per-node structural
features that feed the context-aware risk score:
  - degree centrality      (how connected a node is)
  - betweenness centrality (how much it sits on paths between others)
  - exposure_hours         (how long the asset/port has been observed)
  - rarity                 (how uncommon the service is across the surface)
  - propagation            (reachable neighbours = blast-radius proxy)

Nodes: the target (domain), each asset (IP), each open port.
Edges: target->asset (resolves-to), asset->port (exposes).
"""
from datetime import datetime, timezone

try:
    import networkx as nx
except Exception:  # pragma: no cover
    nx = None


def build_graph(recon_result: dict, exposure_hours: dict = None):
    """Return (graph, features) where features maps node -> feature dict.

    exposure_hours: optional {node_id: hours_observed} to inject temporal data.
    """
    if nx is None:
        raise RuntimeError("networkx is required for ASEG; pip install networkx")

    exposure_hours = exposure_hours or {}
    g = nx.Graph()
    target = recon_result["target"]
    g.add_node(target, kind="target")

    # Count service occurrences to derive rarity.
    service_counts = {}
    for a in recon_result.get("assets", []):
        for p in a.get("ports", []):
            service_counts[p.get("service", "unknown")] = \
                service_counts.get(p.get("service", "unknown"), 0) + 1
    total_ports = max(1, sum(service_counts.values()))

    for a in recon_result.get("assets", []):
        ip = a["ip"]
        g.add_node(ip, kind="asset")
        g.add_edge(target, ip, kind="resolves_to")
        for p in a.get("ports", []):
            node = f"{ip}:{p['port']}"
            svc = p.get("service", "unknown")
            rarity = 1.0 - (service_counts.get(svc, 1) / total_ports)  # rarer -> higher
            g.add_node(node, kind="port", service=svc,
                       product=p.get("product", ""), rarity=round(rarity, 3))
            g.add_edge(ip, node, kind="exposes")

    features = compute_features(g, exposure_hours)
    return g, features


def compute_features(g, exposure_hours: dict = None) -> dict:
    exposure_hours = exposure_hours or {}
    degree = nx.degree_centrality(g)
    try:
        between = nx.betweenness_centrality(g)
    except Exception:
        between = {n: 0.0 for n in g.nodes}

    n_nodes = max(1, g.number_of_nodes())
    features = {}
    for node, data in g.nodes(data=True):
        # propagation = fraction of the graph reachable from this node (blast radius)
        try:
            reach = len(nx.node_connected_component(g, node)) - 1
        except Exception:
            reach = 0
        features[node] = {
            "kind": data.get("kind"),
            "service": data.get("service"),
            "product": data.get("product", ""),
            "degree_centrality": round(degree.get(node, 0.0), 4),
            "betweenness_centrality": round(between.get(node, 0.0), 4),
            "rarity": data.get("rarity", 0.0),
            "exposure_hours": float(exposure_hours.get(node, 0.0)),
            "propagation": round(reach / n_nodes, 4),
        }
    return features


def graph_to_dict(g, features: dict) -> dict:
    """Serialise the graph for the API / dashboard (nodes + links)."""
    nodes = [{"id": n, **features.get(n, {})} for n in g.nodes]
    links = [{"source": u, "target": v, "kind": d.get("kind", "")}
             for u, v, d in g.edges(data=True)]
    return {"nodes": nodes, "links": links,
            "generated_at": datetime.now(timezone.utc).isoformat()}
