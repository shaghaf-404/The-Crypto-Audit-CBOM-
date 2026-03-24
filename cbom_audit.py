#!/usr/bin/env python3
"""
cbom_audit.py — Cryptographic Bill of Materials (CBOM) Generator
=================================================================
Dynamically scans a Python/Flask application for cryptographic touchpoints
using AST analysis, dependency scanning, and config file inspection.

Usage:
  python cbom_audit.py --path ./sample_flask_app
  python cbom_audit.py --path ./sample_flask_app --output ./reports --format all
  python cbom_audit.py --path . --mosca-z 2033 --mosca-y 4 --no-plot --verbose

Outputs (selectable via --format):
  - markdown    →  CBOM.md
  - json        →  cbom.json  (CI/CD friendly)
  - cyclonedx   →  cbom.cdx.json  (industry standard)
  - all         →  all three + dashboard PNG
"""

import argparse
import logging
import sys
import os
from pathlib import Path
from cbom_scanner.scanner import CryptoScanner
from cbom_scanner.exporters import export_markdown, export_json, export_cyclonedx

# ── Try importing optional dependencies gracefully ────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")   # non-interactive backend — safe for all environments
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

# ── Local scanner modules ─────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from cbom_scanner import CryptoScanner, export_markdown, export_json, export_cyclonedx
from cbom_scanner.scanner import CryptoFinding
from cbom_scanner.exporters import _mosca_status

# ──────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CBOM Auditor — Cryptographic Bill of Materials Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cbom_audit.py --path ./myapp
  python cbom_audit.py --path ./myapp --format all --output ./reports
  python cbom_audit.py --path . --mosca-z 2033 --mosca-y 4 --no-plot
        """
    )
    p.add_argument("--path",     "-p", default=".", metavar="DIR",
                   help="Root directory of the application to scan (default: .)")
    p.add_argument("--output",   "-o", default="./cbom_output", metavar="DIR",
                   help="Output directory for reports (default: ./cbom_output)")
    p.add_argument("--format",   "-f", default="all",
                   choices=["markdown", "json", "cyclonedx", "all"],
                   help="Output format (default: all)")
    p.add_argument("--mosca-z",  type=int, default=2035, metavar="YEAR",
                   help="Estimated year quantum computer breaks RSA (default: 2035)")
    p.add_argument("--mosca-y",  type=int, default=5,    metavar="YEARS",
                   help="Years needed to complete migration (default: 5)")
    p.add_argument("--no-plot",  action="store_true",
                   help="Skip dashboard PNG generation")
    p.add_argument("--verbose",  "-v", action="store_true",
                   help="Enable debug logging")
    p.add_argument("--app-name", default=None, metavar="NAME",
                   help="Application name for report headers (default: folder name)")
    return p


# ──────────────────────────────────────────────────────────────────────────────
# TERMINAL TABLE — pretty-print findings
# ──────────────────────────────────────────────────────────────────────────────

RISK_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m",
    "MEDIUM":   "\033[94m", "LOW":  "\033[92m",
}
RESET = "\033[0m"

def print_summary(findings: list, mosca_z: int, mosca_y: int):
    current = 2026
    vulnerable = [f for f in findings if f.vulnerable]
    safe       = [f for f in findings if not f.vulnerable]

    print("\n" + "═" * 78)
    print("  CBOM AUDIT RESULTS")
    print("═" * 78)
    print(f"  Total findings     : {len(findings)}")
    print(f"  Quantum-vulnerable : {len(vulnerable)}")
    print(f"  Quantum-safe       : {len(safe)}")
    print(f"  Mosca Z={mosca_z}  Y={mosca_y}yr  Current={current}")
    print("═" * 78)

    src_map = {"ast_scan": "AST", "dep_scan": "DEP", "config_scan": "CFG"}
    print(f"\n  {'#':<4} {'Source':<5} {'Risk':<10} {'Tier':<5} {'Mosca':<9} {'Component / Algorithm'}")
    print("  " + "─" * 74)
    for i, f in enumerate(findings, 1):
        color  = RISK_COLOR.get(f.risk_level, "")
        status = _mosca_status(f, mosca_z, mosca_y, current)
        src    = src_map.get(f.source, f.source[:3].upper())
        comp   = f"{f.component[:35]:<35}  {f.algorithm[:22]}"
        print(f"  {i:<4} {src:<5} {color}{f.risk_level:<10}{RESET} {f.migration_tier:<5} {status:<9} {comp}")


# ──────────────────────────────────────────────────────────────────────────────
# DASHBOARD VISUALISATION
# ──────────────────────────────────────────────────────────────────────────────

def generate_dashboard(findings: list, output_path: Path, mosca_z: int, mosca_y: int):
    if not HAS_PLOT:
        logging.getLogger("cbom").warning("matplotlib not installed — skipping plot. pip install matplotlib numpy")
        return

    current    = 2026
    vulnerable = [f for f in findings if f.vulnerable]

    plt.style.use("dark_background")
    fig = plt.figure(figsize=(18, 11), facecolor="#0d1117")
    fig.suptitle("CBOM — Quantum Risk Dashboard", fontsize=17,
                 fontweight="bold", color="white", y=0.98)

    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

    # ── Panel 1: Mosca bars (vulnerable only) ──────────────────────────────
    ax1 = fig.add_subplot(gs[0, :])
    ax1.set_facecolor("#1a1f2e")
    for sp in ax1.spines.values(): sp.set_color("#333344")

    labels  = [f"{f.source[:3].upper()} | {f.component[:32]}" for f in vulnerable]
    x_vals  = [f.data_shelf_life_years for f in vulnerable]
    y_vals  = [mosca_y] * len(vulnerable)
    y_pos   = range(len(vulnerable))
    risk_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff9944", "MEDIUM": "#4499ff", "LOW": "#44cc66"}
    bar_colors  = [risk_colors.get(f.risk_level, "#888888") for f in vulnerable]

    ax1.barh(y_pos, x_vals,         color=bar_colors,  alpha=0.85, height=0.5, label="X — data shelf life")
    ax1.barh(y_pos, y_vals, left=x_vals, color="#00d4ff", alpha=0.60, height=0.5, label=f"Y — migration ({mosca_y}yr)")
    ax1.axvline(mosca_z - current, color="#ff6b6b", linewidth=2.5, linestyle="--",
                label=f"Z — quantum collapse ~{mosca_z}")

    ax1.set_yticks(list(y_pos))
    ax1.set_yticklabels(labels, fontsize=7.5, color="#cccccc")
    ax1.set_xlabel("Years from today", color="#aaaaaa")
    ax1.set_title("Mosca Theorem — X + Y vs Z  (bar crossing red = OVERDUE)", color="white", fontsize=10)
    ax1.legend(fontsize=8, labelcolor="white", facecolor="#1a1f2e", loc="lower right")
    ax1.tick_params(colors="#aaaaaa")

    # ── Panel 2: Source breakdown pie ──────────────────────────────────────
    ax2 = fig.add_subplot(gs[1, 0])
    ax2.set_facecolor("#1a1f2e")
    src_counts = {"AST Scan": 0, "Dep Scan": 0, "Config Scan": 0}
    for f in findings:
        k = {"ast_scan": "AST Scan", "dep_scan": "Dep Scan", "config_scan": "Config Scan"}.get(f.source, "Other")
        src_counts[k] = src_counts.get(k, 0) + 1
    wedges, texts, autos = ax2.pie(
        src_counts.values(), labels=src_counts.keys(),
        colors=["#7c3aed", "#00d4ff", "#ff9944"],
        autopct="%1.0f%%", startangle=140,
        textprops={"color": "white", "fontsize": 8}, pctdistance=0.75
    )
    for at in autos: at.set_fontsize(9)
    ax2.set_title("Findings by Source", color="white", fontsize=10)

    # ── Panel 3: Migration tier bar ─────────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, 1])
    ax3.set_facecolor("#1a1f2e")
    for sp in ax3.spines.values(): sp.set_color("#333344")
    tier_labels = ["Tier 1\nNow", "Tier 2\nSoon", "Tier 3\nScheduled", "Tier 4\nSafe"]
    tier_counts = [sum(1 for f in findings if f.migration_tier == t) for t in [1,2,3,4]]
    tier_colors = ["#ff4444", "#ff9944", "#4499ff", "#44cc66"]
    bars = ax3.bar(tier_labels, tier_counts, color=tier_colors, alpha=0.88, width=0.55)
    for bar, val in zip(bars, tier_counts):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                 str(val), ha="center", color="white", fontsize=12, fontweight="bold")
    ax3.set_title("Migration Tiers", color="white", fontsize=10)
    ax3.set_ylabel("Findings", color="#aaaaaa")
    ax3.tick_params(colors="#aaaaaa")
    ax3.set_ylim(0, max(tier_counts or [1]) + 2)

    # ── Panel 4: Risk level bar ─────────────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.set_facecolor("#1a1f2e")
    for sp in ax4.spines.values(): sp.set_color("#333344")
    risk_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    risk_counts = [sum(1 for f in findings if f.risk_level == r) for r in risk_order]
    bars2 = ax4.bar(risk_order, risk_counts, color=["#ff4444","#ff9944","#4499ff","#44cc66"], alpha=0.88, width=0.55)
    for bar, val in zip(bars2, risk_counts):
        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                 str(val), ha="center", color="white", fontsize=12, fontweight="bold")
    ax4.set_title("Risk Level Distribution", color="white", fontsize=10)
    ax4.set_ylabel("Findings", color="#aaaaaa")
    ax4.tick_params(colors="#aaaaaa")
    ax4.set_ylim(0, max(risk_counts or [1]) + 2)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()
    logging.getLogger("cbom").info("Dashboard saved: %s", output_path)


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # ── Configure logging ──────────────────────────────────────────────────
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level  = level,
        format = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt= "%H:%M:%S",
    )
    log = logging.getLogger("cbom")

    # ── Resolve paths ──────────────────────────────────────────────────────
    project_root = Path(args.path).resolve()
    output_dir   = Path(args.output).resolve()
    app_name     = args.app_name or project_root.name
    output_dir.mkdir(parents=True, exist_ok=True)

    if not project_root.exists():
        log.error("Project path does not exist: %s", project_root)
        sys.exit(1)

    log.info("Scanning: %s", project_root)
    log.info("Output:   %s", output_dir)
    log.info("Mosca:    Z=%d  Y=%d yr", args.mosca_z, args.mosca_y)

    # ── Run scan ───────────────────────────────────────────────────────────
    scanner  = CryptoScanner(str(project_root))
    findings = scanner.run()

    if not findings:
        log.warning("No cryptographic findings detected.")
        sys.exit(0)

    # ── Terminal output ────────────────────────────────────────────────────
    print_summary(findings, args.mosca_z, args.mosca_y)

    # ── Export ─────────────────────────────────────────────────────────────
    fmt = args.format

    if fmt in ("markdown", "all"):
        export_markdown(
            findings, app_name,
            output_dir / "CBOM.md",
            mosca_z=args.mosca_z, mosca_y=args.mosca_y
        )
        log.info("✓ Markdown  → %s/CBOM.md", output_dir)

    if fmt in ("json", "all"):
        export_json(findings, output_dir / "cbom.json")
        log.info("✓ JSON      → %s/cbom.json", output_dir)

    if fmt in ("cyclonedx", "all"):
        export_cyclonedx(findings, app_name, output_dir / "cbom.cdx.json")
        log.info("✓ CycloneDX → %s/cbom.cdx.json", output_dir)

    if not args.no_plot and fmt == "all":
        generate_dashboard(
            findings,
            output_dir / "cbom_dashboard.png",
            args.mosca_z, args.mosca_y
        )
        log.info("✓ Dashboard → %s/cbom_dashboard.png", output_dir)

    print(f"\n  All reports written to: {output_dir}\n")


if __name__ == "__main__":
    main()
