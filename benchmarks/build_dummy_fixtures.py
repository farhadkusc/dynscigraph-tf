#!/usr/bin/env python3
"""Write data/dummy for one of the three research repositories.

Organization names are scenario labels. Nothing written here is a feed,
measurement, log, or policy from the named institution.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "dummy"
SEED = 20261020

STATEMENT = (
    "Organization names are scenario labels for the class of institution a test "
    "row stands in for. No record in data/dummy is a measurement, feed, log, "
    "advisory, or policy from that organization. This project is not affiliated "
    "with and is not endorsed by any of them. benchmarks/results/dummy_evaluation.json "
    "is a fixture check. Do not cite it as an experimental result."
)

FFRDC_NOTE = (
    "policy_profile=nss marks a DoD FFRDC-shaped fixture, not a description of that laboratory's network."
)
STACKS = (
    "SYN-STACK-CIVIL",
    "SYN-STACK-DEFENSE",
    "SYN-STACK-LAB",
    "SYN-STACK-IBM",
    "SYN-STACK-RESEARCH",
)
DEFENSE_IDS = {
    "FED-DOD",
    "FED-NSA",
    "FED-USCYBERCOM",
    "FED-DARPA",
    "FED-IARPA",
    "FED-ODNI",
    "FED-FBI",
}
LAB_STACK_IDS = {
    "RES-MIT-LL",
    "RES-CMU-SEI",
    "RES-JHU-APL",
}
TACTICS = (
    "collection",
    "credential-access",
    "defense-evasion",
    "discovery",
    "lateral-movement",
    "command-and-control",
)

COLUMNS = [
    "org_id",
    "display_name",
    "klass",
    "country",
    "sector",
    "policy_profile",
    "committee_n",
    "assumed_one_way_ms",
    "scenario_threat",
    "scenario_load",
    "scenario_fallback",
    "notes",
]


def _row(org_id, name, klass, country, sector, policy, n, delay, threat, load, fallback, notes=""):
    return {
        "org_id": org_id,
        "display_name": name,
        "klass": klass,
        "country": country,
        "sector": sector,
        "policy_profile": policy,
        "committee_n": int(n),
        "assumed_one_way_ms": int(delay),
        "scenario_threat": threat,
        "scenario_load": float(load),
        "scenario_fallback": int(fallback),
        "notes": notes,
    }


def organizations() -> list[dict]:
    rows: list[dict] = []
    departments = [
        ("FED-USDA", "U.S. Department of Agriculture", "food-agriculture", "cnsa-aligned", 16, 40, "LOW", 0.35, 0),
        ("FED-DOC", "U.S. Department of Commerce", "commerce", "cnsa-aligned", 16, 40, "LOW", 0.40, 0),
        ("FED-DOD", "U.S. Department of Defense", "defense", "nss", 64, 20, "HIGH", 0.50, 0),
        ("FED-ED", "U.S. Department of Education", "education", "cnsa-aligned", 16, 40, "LOW", 0.30, 0),
        ("FED-DOE", "U.S. Department of Energy", "energy", "nss", 16, 20, "LOW", 0.48, 0),
        ("FED-HHS", "U.S. Department of Health and Human Services", "healthcare", "cnsa-aligned", 16, 40, "LOW", 0.42, 0),
        ("FED-DHS", "U.S. Department of Homeland Security", "government-facilities", "nss", 16, 25, "LOW", 0.55, 0),
        ("FED-HUD", "U.S. Department of Housing and Urban Development", "government-facilities", "cnsa-aligned", 16, 40, "LOW", 0.22, 0),
        ("FED-DOJ", "U.S. Department of Justice", "government-facilities", "nss", 16, 25, "LOW", 0.46, 0),
        ("FED-DOL", "U.S. Department of Labor", "government-facilities", "cnsa-aligned", 16, 40, "LOW", 0.27, 0),
        ("FED-DOS", "U.S. Department of State", "government-facilities", "nss", 16, 40, "HIGH", 0.38, 0),
        ("FED-DOI", "U.S. Department of the Interior", "government-facilities", "cnsa-aligned", 16, 40, "LOW", 0.24, 0),
        ("FED-TREAS", "U.S. Department of the Treasury", "finance", "nss", 16, 20, "LOW", 0.60, 0),
        ("FED-DOT", "U.S. Department of Transportation", "transportation", "cnsa-aligned", 16, 40, "LOW", 0.33, 1),
        ("FED-VA", "U.S. Department of Veterans Affairs", "healthcare", "cnsa-aligned", 16, 30, "LOW", 0.44, 0),
    ]
    for item in departments:
        rows.append(_row(item[0], item[1], "federal-department", "US", *item[2:]))

    components = [
        ("FED-CISA", "Cybersecurity and Infrastructure Security Agency", "government-facilities", "nss", 16, 20, "LOW", 0.50, 0),
        ("FED-NIST", "National Institute of Standards and Technology", "standards", "cnsa-aligned", 16, 10, "LOW", 0.36, 0),
        ("FED-NSA", "National Security Agency", "intelligence", "nss", 64, 20, "HIGH", 0.40, 0),
        ("FED-FBI", "Federal Bureau of Investigation", "law-enforcement", "nss", 16, 20, "HIGH", 0.45, 0),
        ("FED-USCYBERCOM", "U.S. Cyber Command", "defense", "nss", 64, 20, "HIGH", 0.52, 0),
        ("FED-DARPA", "Defense Advanced Research Projects Agency", "defense", "nss", 16, 15, "LOW", 0.34, 0),
        ("FED-IARPA", "Intelligence Advanced Research Projects Activity", "intelligence", "nss", 16, 15, "LOW", 0.31, 0),
        ("FED-NSF", "National Science Foundation", "science", "cnsa-aligned", 16, 30, "LOW", 0.29, 0),
        ("FED-NASA", "National Aeronautics and Space Administration", "science", "cnsa-aligned", 16, 30, "LOW", 0.37, 0),
        ("FED-ODNI", "Office of the Director of National Intelligence", "intelligence", "nss", 64, 20, "HIGH", 0.41, 0),
        ("FED-FCC", "Federal Communications Commission", "communications", "cnsa-aligned", 16, 40, "LOW", 0.26, 0),
        ("FED-NRC", "Nuclear Regulatory Commission", "nuclear", "nss", 16, 20, "HIGH", 0.33, 0),
        ("FED-EPA", "Environmental Protection Agency", "water-environment", "cnsa-aligned", 16, 40, "LOW", 0.28, 0),
        ("FED-SEC", "U.S. Securities and Exchange Commission", "finance", "cnsa-aligned", 16, 20, "LOW", 0.47, 0),
        ("FED-FRB", "Board of Governors of the Federal Reserve System", "finance", "cnsa-aligned", 16, 10, "LOW", 0.58, 0),
        ("FED-TSA", "Transportation Security Administration", "transportation", "nss", 16, 25, "HIGH", 0.39, 0),
        ("FED-USSS", "U.S. Secret Service", "finance", "nss", 16, 20, "HIGH", 0.36, 0),
        ("FED-USCG", "U.S. Coast Guard", "transportation", "nss", 16, 30, "LOW", 0.34, 0),
    ]
    for item in components:
        rows.append(_row(item[0], item[1], "federal-component", "US", *item[2:]))

    labs = [
        ("FEDLAB-AMES", "Ames Laboratory"),
        ("FEDLAB-ANL", "Argonne National Laboratory"),
        ("FEDLAB-BNL", "Brookhaven National Laboratory"),
        ("FEDLAB-FNAL", "Fermi National Accelerator Laboratory"),
        ("FEDLAB-INL", "Idaho National Laboratory"),
        ("FEDLAB-LBNL", "Lawrence Berkeley National Laboratory"),
        ("FEDLAB-LLNL", "Lawrence Livermore National Laboratory"),
        ("FEDLAB-LANL", "Los Alamos National Laboratory"),
        ("FEDLAB-NETL", "National Energy Technology Laboratory"),
        ("FEDLAB-NREL", "National Renewable Energy Laboratory"),
        ("FEDLAB-ORNL", "Oak Ridge National Laboratory"),
        ("FEDLAB-PNNL", "Pacific Northwest National Laboratory"),
        ("FEDLAB-PPPL", "Princeton Plasma Physics Laboratory"),
        ("FEDLAB-SLAC", "SLAC National Accelerator Laboratory"),
        ("FEDLAB-SNL", "Sandia National Laboratories"),
        ("FEDLAB-SRNL", "Savannah River National Laboratory"),
        ("FEDLAB-JLAB", "Thomas Jefferson National Accelerator Facility"),
    ]
    for org_id, name in labs:
        rows.append(_row(org_id, name, "national-laboratory", "US", "energy", "nss", 16, 10, "LOW", 0.55, 0))

    ibm = [
        ("IBM-YORKTOWN", "IBM Research — Thomas J. Watson Research Center", "US", 16, 5, 0.40, 0, ""),
        ("IBM-ZURICH", "IBM Research Zurich", "CH", 16, 5, 0.40, 1, "Fallback is a scenario switch, not an outage report."),
        ("IBM-ALMADEN", "IBM Research Almaden", "US", 16, 5, 0.30, 0, ""),
        ("IBM-TOKYO", "IBM Research Tokyo", "JP", 16, 8, 0.28, 0, ""),
        ("IBM-HAIFA", "IBM Research Haifa", "IL", 16, 8, 0.33, 0, ""),
        ("IBM-INDIA", "IBM Research India", "IN", 16, 8, 0.45, 0, ""),
        (
            "IBM-QUANTUM",
            "IBM Quantum",
            "US",
            4,
            5,
            0.20,
            0,
            "Scenario label for a fictional research network. Not an IBM Quantum device, runtime, calibration, or published workload.",
        ),
        ("IBM-XFORCE", "IBM X-Force", "US", 16, 5, 0.82, 0, "Scenario label. Not an X-Force incident feed."),
        ("IBM-SECURITY", "IBM Security", "US", 16, 5, 0.25, 0, ""),
        (
            "IBM-FEDERAL",
            "IBM Federal",
            "US",
            16,
            20,
            0.90,
            0,
            "Contract-boundary scenario. Not a statement about an IBM federal system.",
        ),
    ]
    for org_id, name, country, n, delay, load, fallback, notes in ibm:
        policy = "nss" if org_id == "IBM-FEDERAL" else "commercial"
        rows.append(_row(org_id, name, "ibm", country, "technology", policy, n, delay, "LOW", load, fallback, notes))

    research = [
        ("RES-MIT-CSAIL", "MIT Computer Science and Artificial Intelligence Laboratory", "US", "academic", ""),
        ("RES-MIT-LL", "MIT Lincoln Laboratory", "US", "nss", FFRDC_NOTE),
        ("RES-STANFORD", "Stanford University", "US", "academic", ""),
        ("RES-CMU-CYLAB", "Carnegie Mellon University CyLab", "US", "academic", ""),
        ("RES-CMU-SEI", "Carnegie Mellon Software Engineering Institute", "US", "nss", FFRDC_NOTE),
        ("RES-BERKELEY", "University of California, Berkeley", "US", "academic", ""),
        ("RES-GATECH", "Georgia Institute of Technology", "US", "academic", ""),
        ("RES-CALTECH", "California Institute of Technology", "US", "academic", ""),
        ("RES-PRINCETON", "Princeton University", "US", "academic", ""),
        ("RES-HARVARD", "Harvard University", "US", "academic", ""),
        ("RES-COLUMBIA", "Columbia University", "US", "academic", ""),
        ("RES-CORNELL", "Cornell University", "US", "academic", ""),
        ("RES-UIUC", "University of Illinois Urbana-Champaign", "US", "academic", ""),
        ("RES-PURDUE", "Purdue University CERIAS", "US", "academic", ""),
        ("RES-MICHIGAN", "University of Michigan", "US", "academic", ""),
        ("RES-OXFORD", "University of Oxford", "GB", "academic", ""),
        ("RES-CAMBRIDGE", "University of Cambridge", "GB", "academic", ""),
        ("RES-ETH", "ETH Zurich", "CH", "academic", ""),
        ("RES-EPFL", "EPFL", "CH", "academic", ""),
        ("RES-MPI-SP", "Max Planck Institute for Security and Privacy", "DE", "academic", ""),
        ("RES-INRIA", "Inria", "FR", "academic", ""),
        ("RES-TSINGHUA", "Tsinghua University", "CN", "academic", ""),
        ("RES-NUS", "National University of Singapore", "SG", "academic", ""),
        ("RES-WEIZMANN", "Weizmann Institute of Science", "IL", "academic", ""),
        ("RES-TECHNION", "Technion — Israel Institute of Technology", "IL", "academic", ""),
        ("RES-TORONTO", "University of Toronto", "CA", "academic", ""),
        ("RES-WATERLOO", "University of Waterloo", "CA", "academic", ""),
        ("RES-KAIST", "KAIST", "KR", "academic", ""),
        ("RES-U-TOKYO", "University of Tokyo", "JP", "academic", ""),
        ("RES-TNO", "TNO", "NL", "academic", ""),
        ("RES-FRAUNHOFER", "Fraunhofer AISEC", "DE", "academic", ""),
        ("RES-DATA61", "CSIRO's Data61", "AU", "academic", ""),
        ("RES-JHU-APL", "Johns Hopkins University Applied Physics Laboratory", "US", "nss", FFRDC_NOTE),
        ("RES-SRI", "SRI International", "US", "academic", ""),
        ("RES-IITD", "Indian Institute of Technology Delhi", "IN", "academic", ""),
        ("RES-UCL", "University College London", "GB", "academic", ""),
        ("RES-COSIC", "KU Leuven COSIC", "BE", "academic", ""),
        ("RES-RUB", "Ruhr University Bochum", "DE", "academic", ""),
        ("RES-NYU", "New York University", "US", "academic", ""),
        ("RES-TAMU", "Texas A&M University", "US", "academic", ""),
        ("RES-UMD", "University of Maryland", "US", "academic", ""),
        ("RES-UCSD", "University of California, San Diego", "US", "academic", ""),
        ("RES-UW", "University of Washington", "US", "academic", ""),
        ("RES-PRINCETON-CITP", "Princeton Center for Information Technology Policy", "US", "academic", ""),
        ("RES-BERKELEY-CLTC", "UC Berkeley Center for Long-Term Cybersecurity", "US", "academic", ""),
        ("RES-OXFORD-GCI", "Oxford Global Cyber Security Capacity Centre", "GB", "academic", ""),
    ]
    acad_i = 0
    for org_id, name, country, policy, notes in research:
        if policy == "nss":
            rows.append(_row(org_id, name, "research-center", country, "science", "nss", 16, 15, "LOW", 0.50, 0, notes))
            continue
        load = 0.86 if acad_i % 3 == 0 else 0.32
        fallback = 1 if org_id == "RES-ETH" else 0
        acad_i += 1
        rows.append(
            _row(org_id, name, "research-center", country, "science", "academic", 4, 20, "LOW", load, fallback, notes)
        )
    ids = [r["org_id"] for r in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate org_id")
    return rows


def family_of(org: dict) -> str:
    if org["klass"] == "national-laboratory" or org["org_id"] in LAB_STACK_IDS:
        return "SYN-STACK-LAB"
    if org["klass"] == "ibm":
        return "SYN-STACK-IBM"
    if org["klass"] == "research-center":
        return "SYN-STACK-RESEARCH"
    if org["org_id"] in DEFENSE_IDS:
        return "SYN-STACK-DEFENSE"
    return "SYN-STACK-CIVIL"


def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def write_organizations(orgs: list[dict]) -> None:
    _write_csv(OUT / "organizations.csv", orgs, COLUMNS)


def write_graph(orgs: list[dict]) -> None:
    by: dict[str, list[dict]] = defaultdict(list)
    for org in orgs:
        by[family_of(org)].append(org)
    tech_of: dict[str, list[str]] = {}
    meta: dict[str, dict] = {}
    k = 1
    for fam in STACKS:
        tech_of[fam] = []
        for j in range(8):
            tid = f"SYN-T{k:03d}"
            k += 1
            tech_of[fam].append(tid)
            meta[tid] = {
                "technique_name": f"Synthetic control {fam} {j + 1}",
                "tactic": TACTICS[j % len(TACTICS)],
            }
    gt = []
    planted = []
    for fam in STACKS:
        members = sorted(by[fam], key=lambda r: r["org_id"])
        techs = tech_of[fam]
        n_anchor = max(1, int(round(0.4 * len(members))))
        other = STACKS[(STACKS.index(fam) + 1) % len(STACKS)]
        noise_tech = tech_of[other][6]
        for i, org in enumerate(members):
            for t_i, tid in enumerate(techs[:6]):
                created = "2023-06-15" if t_i < 5 else "2024-06-15"
                gt.append(_edge(org, tid, meta, created))
            if i < n_anchor:
                for tid in techs[6:]:
                    gt.append(_edge(org, tid, meta, "2024-08-01"))
            else:
                for tid in techs[6:]:
                    gt.append(_edge(org, tid, meta, "2025-04-15"))
                    planted.append(
                        {"group_id": org["org_id"], "technique_id": tid, "created": "2025-04-15", "planted_bridge": 1}
                    )
            if i % 4 == 0:
                gt.append(_edge(org, noise_tech, meta, "2025-05-01"))
                planted.append(
                    {
                        "group_id": org["org_id"],
                        "technique_id": noise_tech,
                        "created": "2025-05-01",
                        "planted_bridge": 0,
                    }
                )
    mt = []
    for fam in STACKS:
        for tid in tech_of[fam]:
            mt.append(
                {
                    "malware_id": fam,
                    "technique_id": tid,
                    "tactic": meta[tid]["tactic"],
                    "created": "2022-06-01",
                }
            )
    gm = [
        {"group_id": org["org_id"], "malware_id": family_of(org), "created": "2022-03-01"}
        for org in orgs
    ]
    sub = []
    for fam in STACKS:
        techs = tech_of[fam]
        for child, parent in zip(techs[1::2], techs[::2]):
            sub.append({"child_id": child, "parent_id": parent, "created": "2022-01-01"})
    _write_csv(
        OUT / "group_technique.csv",
        gt,
        ["group_id", "group_name", "technique_id", "technique_name", "tactic", "created"],
    )
    _write_csv(OUT / "malware_technique.csv", mt, ["malware_id", "technique_id", "tactic", "created"])
    _write_csv(OUT / "group_malware.csv", gm, ["group_id", "malware_id", "created"])
    _write_csv(OUT / "subtechnique.csv", sub, ["child_id", "parent_id", "created"])
    _write_csv(
        OUT / "planted_future.csv",
        planted,
        ["group_id", "technique_id", "created", "planted_bridge"],
    )
    write_catalog()


def _edge(org: dict, tid: str, meta: dict, created: str) -> dict:
    return {
        "group_id": org["org_id"],
        "group_name": org["display_name"],
        "technique_id": tid,
        "technique_name": meta[tid]["technique_name"],
        "tactic": meta[tid]["tactic"],
        "created": created,
    }


def write_catalog() -> None:
    rows = []
    n = 1
    for _ in range(8):
        rows.append(_vuln(n, 0.95, "2024-05-01"))
        n += 1
    for _ in range(40):
        rows.append(_vuln(n, 0.90, "2025-11-01"))
        n += 1
    for _ in range(5):
        rows.append(_vuln(n, 0.04, "2025-11-15"))
        n += 1
    for _ in range(5):
        rows.append(_vuln(n, 0.55, ""))
        n += 1
    for _ in range(180):
        rows.append(_vuln(n, 0.05, ""))
        n += 1
    _write_csv(OUT / "vuln_catalog.csv", rows, ["syn_id", "score", "date_added"])


def _vuln(n: int, score: float, added: str) -> dict:
    return {"syn_id": f"SYN-VULN-{n:05d}", "score": f"{score:.2f}", "date_added": added}


def write_flows(orgs: list[dict]) -> None:
    rng = np.random.default_rng(SEED)
    services = ["http", "smtp", "ftp", "private", "ssh", "domain_u"]
    rates = {"http": 0.82, "smtp": 0.66, "ftp": 0.50, "private": 0.35, "ssh": 0.18, "domain_u": 0.08}
    fields = [
        "org_id",
        "display_name",
        "klass",
        "policy_profile",
        "sector",
        "service",
        "duration",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "serror_rate",
        "same_srv_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_serror_rate",
        "label",
    ]
    rows = []
    for org in orgs:
        for _ in range(20):
            service = services[int(rng.integers(0, len(services)))]
            label = 1 if float(rng.random()) < rates[service] else 0
            rows.append(
                {
                    "org_id": org["org_id"],
                    "display_name": org["display_name"],
                    "klass": org["klass"],
                    "policy_profile": org["policy_profile"],
                    "sector": org["sector"],
                    "service": service,
                    "duration": int(rng.integers(0, 50) + label * rng.integers(0, 200)),
                    "src_bytes": int(rng.integers(0, 500) + label * rng.integers(0, 5000)),
                    "dst_bytes": int(rng.integers(0, 800) * (1 + label)),
                    "count": int(rng.integers(1, 15) + label * rng.integers(5, 60)),
                    "srv_count": int(rng.integers(1, 15) + label * rng.integers(0, 20)),
                    "serror_rate": round(min(1.0, float(rng.random() * 0.1 + label * rng.random() * 0.7)), 4),
                    "same_srv_rate": round(min(1.0, float(rng.random() * 0.3 + (1 - label) * rng.random() * 0.7)), 4),
                    "dst_host_count": int(rng.integers(1, 40) + label * rng.integers(0, 80)),
                    "dst_host_srv_count": int(rng.integers(1, 40)),
                    "dst_host_serror_rate": round(min(1.0, float(rng.random() * 0.1 + label * rng.random() * 0.6)), 4),
                    "label": label,
                }
            )
    _write_csv(OUT / "flows.csv", rows, fields)


def write_scenario() -> None:
    scenario = {
        "kind": "synthetic-exercise",
        "exercise_id": "SYN-EXERCISE-GREY-HARBOR",
        "title": "Grey Harbor",
        "as_of": "2026-04-08",
        "cutoff": "2026-03-31",
        "statement": (
            "Tabletop inject for tests. The adversary, the tool, the sites, and the events are fictional. "
            "Blue-cell identifiers are exercise roles, not breach reports. No listed organization was attacked. "
            "This file is not an incident report, an advisory, or a procedure."
        ),
        "adversary": {
            "id": "SYN-ACTOR-HARBOR",
            "display_name": "Harbor",
            "fictional": True,
            "not_a_real_group": True,
        },
        "tool_id": "SYN-TOOL-HARBOR",
        "tool_seen": "2025-05-01",
        "blue_observer_id": "SYN-CELL-BLUE",
        "sites": [
            {
                "id": "SYN-SITE-RIVER-SWITCH",
                "sector": "energy",
                "description": "Fictional distribution cooperative. Not a real utility.",
            },
            {
                "id": "SYN-SITE-LOCK-METER",
                "sector": "water",
                "description": "Fictional treatment-plant meter network. Not a real utility.",
            },
        ],
        "blue_cell": [
            "FED-DOE",
            "FED-CISA",
            "FEDLAB-INL",
            "IBM-XFORCE",
            "IBM-FEDERAL",
            "RES-CMU-SEI",
        ],
        "out_of_scope": ["IBM-QUANTUM"],
        "phases": [
            {
                "id": "PH0",
                "name": "Quiet baseline",
                "start": "2026-03-01",
                "end": "2026-03-31",
                "threat": "LOW",
            },
            {
                "id": "PH1",
                "name": "Inject",
                "start": "2026-04-01",
                "end": "2026-04-08",
                "threat": "HIGH",
                "service_spoof": "domain_u",
                "signature_lock": "ML-DSA-87",
            },
        ],
        "techniques": [
            {"id": "SYN-TH-01", "name": "Fictional remote service", "tactic": "initial-access", "on_tool": True, "blue_seen": "2025-06-01", "actor_seen": "2025-07-01"},
            {"id": "SYN-TH-02", "name": "Fictional credential use", "tactic": "credential-access", "on_tool": True, "blue_seen": "2025-06-01", "actor_seen": "2025-08-01"},
            {"id": "SYN-TH-03", "name": "Fictional discovery", "tactic": "discovery", "on_tool": True, "blue_seen": "2025-06-01", "actor_seen": "2026-02-01"},
            {"id": "SYN-TH-04", "name": "Fictional lateral movement", "tactic": "lateral-movement", "on_tool": True, "blue_seen": "2025-06-01", "actor_seen": "2026-04-08"},
            {"id": "SYN-TH-05", "name": "Fictional collection", "tactic": "collection", "on_tool": True, "blue_seen": "2025-06-01", "actor_seen": "2026-04-08"},
            {"id": "SYN-TH-00", "name": "Fictional impact", "tactic": "impact", "on_tool": False, "blue_seen": "2025-06-01", "actor_seen": None},
        ],
    }
    (OUT / "attack_scenario.json").write_text(json.dumps(scenario, indent=2) + "\n")


def write_manifest(orgs: list[dict]) -> None:
    counts: dict[str, int] = defaultdict(int)
    for org in orgs:
        counts[org["klass"]] += 1
    manifest = {
        "schema_version": "1.0.0",
        "kind": "synthetic-fixture",
        "seed": SEED,
        "n_organizations": len(orgs),
        "counts": dict(counts),
        "scope": {
            "federal_departments": "All 15 U.S. cabinet departments.",
            "federal_components": "Cyber-relevant components only. Not every bureau or field office.",
            "national_laboratories": "The 17 U.S. Department of Energy national laboratories.",
            "ibm": "Named IBM research laboratories and security units, as fictional deployment profiles.",
            "research_centers": "A fixed list of universities and laboratories often used as external points of comparison.",
        },
        "policy_profiles": {
            "nss": "Selector is forced onto the ML-DSA-87 branch. Not a claim that the institution operates an NSS.",
            "cnsa-aligned": "Same strict branch, tagged separately so a federal civilian fixture is not labeled nss.",
            "commercial": "May step down to ML-DSA-65 only under the code's published rule.",
            "academic": "Same selector rule as commercial.",
        },
        "stack_ids": {
            "meaning": "Planted consortium id for the observation-graph fixture. Not an alliance, contract, or threat actor.",
            "values": list(STACKS),
        },
        "exercise": "SYN-EXERCISE-GREY-HARBOR",
        "statement": STATEMENT,
    }
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


def write_readme(repo: str) -> None:
    usage = {
        "dynscigraph-tf": "The observation graph uses the same columns as `data/derived` so `run_cutoff` can score it. Identifiers start with `FED-`, `FEDLAB-`, `IBM-`, `RES-`, `SYN-T`, or `SYN-VULN-`. They are not ATT&CK, CVE, or KEV identifiers. `vuln_catalog.csv` is a separable ranking fixture for the metric code.",
        "quantumshield-qhbft": "Each row is a deployment scenario: committee size `3f+1`, an assumed one-way delay, and a policy profile. `run_dummy` calls `select_signature` and `decision_cost`. Delays are assumptions. Cryptographic microseconds still come only from `data/published_costs.json`.",
        "tecdf-xai": "`flows.csv` has twenty synthetic flows per organization. The service field is a planted neighborhood, not a packet capture from that organization. `run_dummy` scores the file with the same functions as the NSL-KDD benchmark and does not replace `benchmarks/results/evaluation.json`.",
    }[repo]
    text = f"""# Synthetic institution fixtures

**Kind: synthetic. Not a measurement.**

{STATEMENT}

## What is in the directory

| File | Role |
| --- | --- |
| `organizations.csv` | One row per scenario label. |
| `attack_scenario.json` | Grey Harbor tabletop inject. Fictional adversary and fictional sites. |
| `MANIFEST.json` | Counts, seed {SEED}, and the statement above. |

{usage}

## Scope

- All 15 U.S. cabinet departments.
- Cyber-relevant federal components, not every bureau.
- All 17 Department of Energy national laboratories.
- IBM research laboratories, IBM Quantum, IBM X-Force, IBM Security, and an IBM Federal contract-boundary row.
- Universities and research laboratories used as external comparison labels, including three DoD FFRDC-shaped rows (MIT Lincoln Laboratory, CMU SEI, Johns Hopkins APL).

`policy_profile` is an input to a test, not that institution's policy. `assumed_one_way_ms` is not a measured latency. Stack ids (`SYN-STACK-*`) are planted consortia for the graph fixture, not threat groups and not partnerships.

Grey Harbor (`SYN-EXERCISE-GREY-HARBOR`) is the shared attack inject. `SYN-ACTOR-HARBOR` is fictional. The blue-cell ids are exercise roles, not statements that those organizations were compromised. IBM Quantum is listed out of scope so the inject is not read as a device event.

Regenerate with `python3 benchmarks/build_dummy_fixtures.py`. The seed is fixed.
"""
    (OUT / "README.md").write_text(text)


def main() -> None:
    repo = ROOT.name
    OUT.mkdir(parents=True, exist_ok=True)
    orgs = organizations()
    write_organizations(orgs)
    write_manifest(orgs)
    write_readme(repo)
    write_scenario()
    if repo == "dynscigraph-tf":
        write_graph(orgs)
    elif repo == "tecdf-xai":
        write_flows(orgs)
    elif repo != "quantumshield-qhbft":
        raise SystemExit(f"unexpected repository name {repo}")
    print(f"{repo}: {len(orgs)} organizations -> {OUT}")


if __name__ == "__main__":
    main()
