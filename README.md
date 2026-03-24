# 🔐 CBOM Auditor — Cryptographic Bill of Materials Generator

A dynamic security tool that scans Python/Flask applications for cryptographic touchpoints, assesses quantum risk using **Mosca's Theorem**, and generates industry-standard reports to guide post-quantum migration.

---

## 📋 Table of Contents

- [What It Does](#what-it-does)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [How Scanning Works](#how-scanning-works)
- [Output Formats](#output-formats)
- [Mosca's Theorem](#moscas-theorem)
- [Migration Tiers](#migration-tiers)
- [Sample Application](#sample-application)
- [Extending the Tool](#extending-the-tool)

---

## What It Does

CBOM Auditor walks your Python project and discovers **every cryptographic touchpoint** across three scan layers:

| Layer | What it scans | Example findings |
|---|---|---|
| 🐍 **AST Scan** | Python source files (imports + API calls) | `rsa.generate_private_key`, `jwt.encode`, `ssl.SSLContext` |
| 📦 **Dependency Scan** | `requirements.txt`, `Pipfile` | `PyJWT`, `paramiko`, `cryptography`, `pycryptodome` |
| ⚙️ **Config Scan** | `nginx.conf`, `sshd_config`, `.env` | TLS cipher suites, SSH key types, env-level secrets |

For every finding, it produces:
- Quantum vulnerability assessment (RSA/ECC = vulnerable, HMAC/bcrypt = safe)
- Mosca Theorem deadline status (OVERDUE / URGENT / SAFE)
- PQC replacement recommendation (NIST-standardised algorithms)
- Migration priority tier (1 = replace now → 4 = no action needed)

---

## Project Structure

```
cbom-auditor/
│
├── cbom_audit.py              # Main entry point — CLI, orchestration, dashboard
│
├── cbom_scanner/
│   ├── __init__.py            # Package exports
│   ├── scanner.py             # AST + dependency + config scanners, CryptoFinding dataclass
│   └── exporters.py          # Markdown, JSON, and CycloneDX output formatters
│
├── sample_app.py              # Example Flask app — target for demo scans
├── requirements.txt           # Project dependencies
│
└── keys/                      # Demo keys (do not use in production)
    ├── private_rsa2048.pem
    ├── public_rsa2048.pem
    ├── server.key
    └── server.crt
```

---

## Installation

**Requirements:** Python 3.9+

```bash
# 1. Clone the repository
git clone https://github.com/your-org/cbom-auditor.git
cd cbom-auditor

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

**Core dependencies:**

| Package | Purpose |
|---|---|
| `matplotlib` + `numpy` | Dashboard PNG generation |
| `Flask`, `PyJWT`, `cryptography` | Required only to run `sample_app.py` |
| All others | Standard library only for the scanner itself |

> **Note:** `matplotlib` and `numpy` are optional. The scanner and all text/JSON exports work without them. Only the dashboard PNG requires them.

---

## Quick Start

```bash
# Scan the included sample Flask app
python cbom_audit.py --path ./sample_app.py

# Scan any project folder and export all formats
python cbom_audit.py --path ./myapp --format all --output ./reports

# Scan with custom Mosca parameters (Z = 2033, Y = 4 years migration time)
python cbom_audit.py --path ./myapp --mosca-z 2033 --mosca-y 4

# Scan without generating the dashboard image
python cbom_audit.py --path ./myapp --no-plot

# Verbose mode (shows every file parsed, every finding detected)
python cbom_audit.py --path ./myapp --verbose
```

---

## CLI Reference

```
usage: cbom_audit.py [-h] [--path DIR] [--output DIR]
                     [--format {markdown,json,cyclonedx,all}]
                     [--mosca-z YEAR] [--mosca-y YEARS]
                     [--no-plot] [--verbose] [--app-name NAME]
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--path` | `-p` | `.` | Root directory of the application to scan |
| `--output` | `-o` | `./cbom_output` | Directory to write all report files |
| `--format` | `-f` | `all` | Output format: `markdown`, `json`, `cyclonedx`, or `all` |
| `--mosca-z` | — | `2035` | Estimated year a quantum computer breaks RSA |
| `--mosca-y` | — | `5` | Years needed to complete your migration |
| `--no-plot` | — | off | Skip dashboard PNG (useful in CI/CD environments) |
| `--verbose` | `-v` | off | Enable debug-level logging |
| `--app-name` | — | folder name | Application name shown in report headers |

---

## How Scanning Works

### 1. AST Scan (`scanner.py → ASTCryptoScanner`)

Parses every `.py` file using Python's built-in `ast` module. It walks the syntax tree and flags:

- **Import statements** — detects crypto-relevant libraries by module name (`jwt`, `cryptography`, `Crypto`, `paramiko`, `ssl`, `hmac`, etc.)
- **Function/method calls** — matches specific API patterns using regex against the source text, e.g.:

```python
rsa.generate_private_key(...)   → CRITICAL — RSA key generation
jwt.encode(..., algorithm="RS256")  → HIGH — JWT with RSA signing
hashlib.md5(...)               → CRITICAL — MD5 is broken
ssl.SSLContext(...)             → HIGH — TLS context created
bcrypt.hashpw(...)             → LOW — quantum-safe
```

### 2. Dependency Scan (`DependencyScanner`)

Reads `requirements.txt` and `Pipfile`, matches each package name against a knowledge base of 20+ crypto-relevant libraries. Flags not just obviously-crypto packages like `cryptography` and `PyJWT`, but also indirect ones like `requests` (uses TLS), `boto3` (HMAC-SHA256), and `azure-identity` (RSA-signed JWTs).

### 3. Config Scan (`ConfigScanner`)

Scans configuration files (`nginx.conf`, `sshd_config`, `.env`, `*.conf`) using regex patterns to detect:

- Weak TLS cipher suites
- SSLv3 / TLS 1.0 / TLS 1.1 usage
- RSA/DSA/ECDSA key type references
- Hardcoded secrets or key paths in environment files

### 4. Deduplication

Findings are deduplicated by `(component, algorithm, file)` key — the same library detected by both AST and dependency scan appears only once.

### 5. Enrichment

Each finding is automatically enriched with:
- **PQC replacement** — the NIST-standardised post-quantum drop-in (ML-KEM, ML-DSA, SLH-DSA)
- **Data shelf life** — estimated years the encrypted data must remain secure
- **Migration tier** — urgency level (see Migration Tiers below)
- **QKD flag** — whether Quantum Key Distribution hardware is advised

---

## Output Formats

All outputs are written to the `--output` directory.

### `CBOM.md` — Markdown Report

Human-readable GitHub-flavoured Markdown. Includes a summary table, a per-finding index table, and a full detailed entry for each finding with Mosca status, PQC recommendation, and notes. Ideal for attaching to pull requests or security reviews.

### `cbom.json` — Plain JSON

Machine-readable flat JSON array of all findings. Every field from `CryptoFinding` is exported. Designed for ingestion by CI/CD pipelines, custom dashboards, or further scripting.

```json
{
  "scan_date": "2026-03-25",
  "findings": [
    {
      "source": "ast_scan",
      "component": "RSA key generation",
      "location": "sample_app.py:52",
      "algorithm": "RSA",
      "risk_level": "CRITICAL",
      "mosca_status": "OVERDUE",
      ...
    }
  ]
}
```

### `cbom.cdx.json` — CycloneDX 1.5 CBOM

Industry-standard format following the [CycloneDX specification](https://cyclonedx.org/capabilities/cbom/). Ingestible by tools like **Dependency-Track**, **grype**, and **trivy**. Each finding is exported as a `cryptographic-asset` component with `cryptoProperties`, OID mappings, and evidence occurrences.

### `cbom_dashboard.png` — Visual Dashboard

A 4-panel matplotlib dashboard:

| Panel | Content |
|---|---|
| Top (full width) | Mosca Theorem horizontal bar chart — X + Y vs Z per vulnerable component |
| Bottom-left | Pie chart — findings by source (AST / Deps / Config) |
| Bottom-centre | Bar chart — migration tier distribution |
| Bottom-right | Bar chart — risk level distribution (CRITICAL / HIGH / MEDIUM / LOW) |

---

## Mosca's Theorem

Mosca's Theorem determines **whether you have already run out of time** to migrate a given piece of cryptography before a quantum computer could break it.

```
X + Y > Z  →  You are OVERDUE. Migration must start immediately.
X + Y ≤ Z  →  URGENT, but there is still time.
```

| Variable | Meaning | Default |
|---|---|---|
| **X** | How long the encrypted data must remain secure (data shelf life) | Per-component |
| **Y** | How many years your migration will take | `5` (configurable via `--mosca-y`) |
| **Z** | How many years until a quantum computer can break RSA | `2035` (configurable via `--mosca-z`) |

Both Z and Y are configurable at the CLI so you can run best-case and worst-case scenarios side by side.

---

## Migration Tiers

| Tier | Label | When to act | Typical components |
|---|---|---|---|
| **1** | Replace NOW | Immediately — Mosca deadline passed or critical data exposure | TLS termination, PKI root CA, RSA key wrapping, SSH host keys |
| **2** | Replace soon | Within 12 months | JWT signing keys, mTLS service certs |
| **3** | Scheduled | Within 2–3 years | Code signing, AES-128 upgrades, config hardening |
| **4** | Safe / No change | No action required | bcrypt, HMAC-SHA256, SHA-256/512 |

---

## Sample Application

`sample_app.py` is a realistic Flask application designed to exercise every scan path. It intentionally uses:

- **RS256 JWT signing** via `PyJWT` + RSA-2048 private key
- **RSA-2048 key generation** via `cryptography` library
- **ECDSA / ECC P-256** key generation
- **RSA-OAEP encryption** via `PyCryptodome`
- **Fernet (AES-128-CBC)** symmetric encryption
- **bcrypt** password hashing (quantum-safe)
- **HMAC-SHA256** session cookie signing (quantum-safe)
- **TLS 1.3 context** creation via `ssl.SSLContext` + cert loading
- **SSH via Paramiko** with ECDSA key
- **itsdangerous** URL-safe token serialization

Running a scan against it will produce findings across all three scan layers (AST, dependency, and config).

---

## Extending the Tool

### Adding a new library to the knowledge base

Edit `LIBRARY_CRYPTO_MAP` in `scanner.py`:

```python
LIBRARY_CRYPTO_MAP["my-crypto-lib"] = {
    "algorithm": "XYZ-256",
    "purpose":   "Custom field encryption",
    "vulnerable": True,
    "risk":       "HIGH",
}
```

Then add the import alias to `IMPORT_PATTERNS`:

```python
IMPORT_PATTERNS["my_crypto_lib"] = "my-crypto-lib"
```

### Adding a new call-level pattern

Add an entry to `CALL_PATTERNS` in `scanner.py` using a regex string:

```python
CALL_PATTERNS[r"my_module\.sign_with_rsa"] = {
    "algorithm": "RSA-2048",
    "risk":      "CRITICAL",
    "note":      "RSA signing — replace with ML-DSA",
}
```

### Adding a new output format

Create a new function in `exporters.py` following the same signature:

```python
def export_html(findings: List[CryptoFinding], output_path: Path):
    ...
```

Then wire it into `cbom_audit.py` under the `--format` argument choices.

---

## References

- [Strategy-Enterprise-Migration_(QRA)](https://github.com/7elmie/EGQCC/tree/main/Strategy-Enterprise-Migration_(QRA)).
- [NIST Post-Quantum Cryptography Standards (FIPS 203/204/205)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CycloneDX CBOM Specification v1.5](https://cyclonedx.org/capabilities/cbom/)
- [Mosca's Theorem — Michele Mosca, 2015](https://eprint.iacr.org/2015/1075.pdf)
- [OpenSSH PQC hybrid keys (sntrup761x25519)](https://www.openssh.com/releasenotes.html)
- [CRYSTALS-Kyber (ML-KEM) — NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)
- [CRYSTALS-Dilithium (ML-DSA) — NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)
