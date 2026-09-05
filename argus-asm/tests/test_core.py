"""Unit tests for the analytical core (no network required)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import config
from argus.detection.change_detector import detect_changes
from argus.analysis import aseg, risk


def _result(ports):
    return {"target": "t", "assets": [{"ip": "10.0.0.1",
            "ports": [{"port": p, "service": s, "product": pr} for p, s, pr in ports],
            "port_count": len(ports)}], "subdomains": {}}


def test_first_scan_is_all_new():
    cur = _result([(80, "http", "Apache/2.4.7"), (22, "ssh", "OpenSSH_6.6")])
    ev = detect_changes(None, cur)
    types = [e["event_type"] for e in ev]
    assert types.count("new_asset") == 1
    assert types.count("new_port") == 2


def test_new_and_closed_ports():
    prev = _result([(80, "http", "Apache/2.4.7"), (22, "ssh", "OpenSSH_6.6")])
    cur = _result([(80, "http", "Apache/2.4.7"), (443, "https", "nginx/1.25")])
    ev = detect_changes(prev, cur)
    types = {e["event_type"] for e in ev}
    assert "new_port" in types      # 443 appeared
    assert "closed_port" in types   # 22 disappeared


def test_banner_change_detected():
    prev = _result([(80, "http", "Apache/2.4.7")])
    cur = _result([(80, "http", "Apache/2.4.41")])
    ev = detect_changes(prev, cur)
    assert any(e["event_type"] == "banner_changed" for e in ev)


def test_risk_is_capped_and_explainable():
    feat = {"kind": "port", "service": "http", "degree_centrality": 1.0,
            "betweenness_centrality": 1.0, "rarity": 1.0,
            "exposure_hours": 10000, "propagation": 1.0}
    b = risk.score_node(9.5, feat)
    assert b["composite_risk"] <= 10.0
    assert set(b["contributions"]) == {"centrality", "exposure", "rarity", "propagation"}
    assert b["cvss_base"] == 9.5


def test_context_lifts_risk():
    low = {"kind": "port", "degree_centrality": 0.0, "rarity": 0.0,
           "exposure_hours": 0, "propagation": 0.0}
    high = {"kind": "port", "degree_centrality": 0.9, "rarity": 0.9,
            "exposure_hours": 800, "propagation": 0.9}
    assert risk.score_node(7.0, high)["composite_risk"] > \
           risk.score_node(7.0, low)["composite_risk"]


def test_aseg_builds_expected_nodes():
    cur = _result([(80, "http", "Apache"), (22, "ssh", "OpenSSH")])
    g, feats = aseg.build_graph(cur)
    # target + asset + 2 ports = 4 nodes
    assert g.number_of_nodes() == 4
    port_nodes = [n for n, f in feats.items() if f["kind"] == "port"]
    assert len(port_nodes) == 2
    for n in port_nodes:
        assert "degree_centrality" in feats[n]
