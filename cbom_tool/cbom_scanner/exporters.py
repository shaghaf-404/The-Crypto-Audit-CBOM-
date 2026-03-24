"""
cbom_scanner/exporters.py
=========================
Exports scan results to:
  - CycloneDX JSON  (industry standard CBOM format)
  - Markdown report (human-readable GitHub format)
  - JSON dump       (machine-readable, CI/CD friendly)
"""

import json
import datetime
import logging
from pathlib import Path
from typing import List
from .scanner import CryptoFinding

logger = logging.getLogger("cbom.exporters")

RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


# ──────────────────────────────────────────────────────────────────────────────
# CycloneDX JSON exporter  (spec v1.5 — cryptoProperties extension)
# ──────────────────────────────────────────────────────────────────────────────

def export_cyclonedx(findings: List[CryptoFinding], app_name: str, output_path: Path):
    """
    Produces a CycloneDX 1.5 BOM with cryptoProperties for each finding.
    This format is ingestible by tools like Dependency-Track, grype, and trivy.
    Spec: https://cyclonedx.org/docs/1.5/json/
    """
    now = datetime.datetime.utcnow().isoformat() + "Z"

    components = []
    for i, f in enumerate(findings, start=1):
        comp_id = f"cbom-{i:03d}"
        risk_score = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.0}.get(f.risk_level, 3.0)

        component = {
            "type":        "cryptographic-asset",
            "bom-ref":     comp_id,
            "name":        f.component,
            "description": f.purpose,
            "cryptoProperties": {
                "assetType":       _infer_asset_type(f.algorithm),
                "algorithmProperties": {
                    "primitive":          _infer_primitive(f.algorithm),
                    "implementationLevel": "softwareLibrary",
                },
                "relatedCryptoMaterialProperties": {
                    "type": "publicKey" if f.vulnerable else "secretKey",
                },
                "oid": _infer_oid(f.algorithm),
            },
            "evidence": {
                "occurrences": [
                    {
                        "location": f.location,
                        "line":     f.line_number,
                    }
                ]
            },
            "properties": [
                {"name": "cbom:source",            "value": f.source},
                {"name": "cbom:riskLevel",         "value": f.risk_level},
                {"name": "cbom:riskScore",         "value": str(risk_score)},
                {"name": "cbom:quantumVulnerable", "value": str(f.vulnerable)},
                {"name": "cbom:pqcReplacement",    "value": f.pqc_replacement},
                {"name": "cbom:qkdNeeded",         "value": str(f.qkd_needed)},
                {"name": "cbom:dataShelfLife",     "value": f"{f.data_shelf_life_years}yr"},
                {"name": "cbom:migrationTier",     "value": str(f.migration_tier)},
                {"name": "cbom:moscaStatus",       "value": _mosca_status(f)},
                {"name": "cbom:notes",             "value": f.notes},
            ],
        }
        components.append(component)

    bom = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:cbom-{datetime.date.today().isoformat()}",
        "version":      1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor":  "CBOM Auditor",
                    "name":    "cbom_audit.py",
                    "version": "2.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": app_name,
            },
        },
        "components": components,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(bom, f, indent=2)

    logger.info("CycloneDX CBOM written: %s  (%d components)", output_path, len(components))


def _infer_asset_type(algo: str) -> str:
    a = algo.upper()
    if any(x in a for x in ["RSA", "ECC", "ECDSA", "ECDH"]): return "algorithmicAsset"
    if "TLS" in a or "SSL" in a:                               return "certificate"
    if "JWT" in a:                                             return "token"
    return "algorithmicAsset"

def _infer_primitive(algo: str) -> str:
    a = algo.upper()
    if "RSA" in a:      return "publicKeyEncryption"
    if "ECC" in a:      return "signature"
    if "ECDSA" in a:    return "signature"
    if "AES" in a:      return "blockCipher"
    if "SHA" in a:      return "hash"
    if "HMAC" in a:     return "mac"
    if "TLS" in a:      return "keyAgreementProtocol"
    return "other"

def _infer_oid(algo: str) -> str:
    oids = {
        "RSA":      "1.2.840.113549.1.1.1",
        "ECDSA":    "1.2.840.10045.4.3.2",
        "AES-256":  "2.16.840.1.101.3.4.1.42",
        "SHA-256":  "2.16.840.1.101.3.4.2.1",
        "SHA-512":  "2.16.840.1.101.3.4.2.3",
    }
    for key, oid in oids.items():
        if key.upper() in algo.upper():
            return oid
    return ""

def _mosca_status(f: CryptoFinding, z: int = 2035, y: int = 5, current: int = 2026) -> str:
    if not f.vulnerable: return "SAFE"
    xpy = f.data_shelf_life_years + y
    if xpy > (z - current): return "OVERDUE"
    return "URGENT"


# ──────────────────────────────────────────────────────────────────────────────
# Markdown report
# ──────────────────────────────────────────────────────────────────────────────

def export_markdown(findings: List[CryptoFinding], app_name: str, output_path: Path,
                    mosca_z: int = 2035, mosca_y: int = 5):
    current = 2026
    vulnerable   = [f for f in findings if f.vulnerable]
    safe         = [f for f in findings if not f.vulnerable]
    tier_counts  = {t: sum(1 for f in findings if f.migration_tier == t) for t in [1,2,3,4]}

    lines = [
        f"# 🔐 Cryptographic Bill of Materials (CBOM)",
        f"",
        f"> **Application:** `{app_name}`  ",
        f"> **Scan Date:** {datetime.date.today()}  ",
        f"> **Scanner:** cbom_audit.py v2.0 (AST + dependency + config scan)  ",
        f"> **Mosca Parameters:** X (per component) | Y = {mosca_y} years | Z = {mosca_z}  ",
        f"",
        f"---",
        f"",
        f"## 📊 Summary",
        f"",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total findings | {len(findings)} |",
        f"| Quantum-vulnerable | {len(vulnerable)} |",
        f"| Quantum-safe | {len(safe)} |",
        f"| Require QKD hardware | {sum(1 for f in findings if f.qkd_needed)} |",
        f"| Tier 1 — Replace NOW | {tier_counts[1]} |",
        f"| Tier 2 — Replace soon | {tier_counts[2]} |",
        f"| Tier 3 — Scheduled | {tier_counts[3]} |",
        f"| Tier 4 — Safe | {tier_counts[4]} |",
        f"",
        f"---",
        f"",
        f"## 🔍 All Findings",
        f"",
        f"| # | Component | Source | Algorithm | Risk | Tier | Mosca Status | QKD |",
        f"|---|---|---|---|---|---|---|---|",
    ]

    for i, f in enumerate(findings, 1):
        emoji   = RISK_EMOJI.get(f.risk_level, "⚪")
        status  = _mosca_status(f, mosca_z, mosca_y, current)
        s_emoji = "🔴" if status == "OVERDUE" else ("🟡" if status == "URGENT" else "🟢")
        qkd     = "⚠️ YES" if f.qkd_needed else "No"
        src     = {"ast_scan": "🐍 AST", "dep_scan": "📦 Deps", "config_scan": "⚙️ Config"}.get(f.source, f.source)
        lines.append(f"| {i} | {f.component[:40]} | {src} | `{f.algorithm[:25]}` | {emoji} {f.risk_level} | {f.migration_tier} | {s_emoji} {status} | {qkd} |")

    lines += [
        f"",
        f"---",
        f"",
        f"## 🗂️ Detailed Entries",
        f"",
    ]

    for i, f in enumerate(findings, 1):
        emoji  = RISK_EMOJI.get(f.risk_level, "⚪")
        status = _mosca_status(f, mosca_z, mosca_y, current)
        lines += [
            f"### Finding #{i:02d} — {f.component}",
            f"",
            f"| Field | Value |",
            f"|---|---|",
            f"| **Source** | `{f.source}` |",
            f"| **Location** | `{f.location}` |",
            f"| **Algorithm** | `{f.algorithm}` |",
            f"| **Purpose** | {f.purpose} |",
            f"| **Quantum status** | {'⚠️ VULNERABLE' if f.vulnerable else '✅ SAFE'} |",
            f"| **Risk level** | {emoji} {f.risk_level} |",
            f"| **Data shelf life** | {f.data_shelf_life_years} years |",
            f"| **Mosca X+Y** | {f.data_shelf_life_years + mosca_y} vs Z={mosca_z - current} → **{status}** |",
            f"| **PQC replacement** | `{f.pqc_replacement}` |",
            f"| **QKD needed** | {'**YES — QKD hardware required**' if f.qkd_needed else 'No'} |",
            f"| **Migration tier** | Tier {f.migration_tier} |",
            f"| **Notes** | {f.notes} |",
            f"",
            f"---",
            f"",
        ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))
    logger.info("Markdown CBOM written: %s", output_path)


# ──────────────────────────────────────────────────────────────────────────────
# Plain JSON dump — for CI/CD pipelines
# ──────────────────────────────────────────────────────────────────────────────

def export_json(findings: List[CryptoFinding], output_path: Path):
    data = [
        {
            "source":               f.source,
            "component":            f.component,
            "location":             f.location,
            "algorithm":            f.algorithm,
            "purpose":              f.purpose,
            "vulnerable":           f.vulnerable,
            "risk_level":           f.risk_level,
            "pqc_replacement":      f.pqc_replacement,
            "qkd_needed":           f.qkd_needed,
            "data_shelf_life_years":f.data_shelf_life_years,
            "migration_tier":       f.migration_tier,
            "mosca_status":         _mosca_status(f),
            "notes":                f.notes,
            "line_number":          f.line_number,
        }
        for f in findings
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fp:
        json.dump({"scan_date": str(datetime.date.today()), "findings": data}, fp, indent=2)
    logger.info("JSON CBOM written: %s  (%d findings)", output_path, len(data))
