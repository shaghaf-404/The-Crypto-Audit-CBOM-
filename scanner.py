"""
cbom_scanner/scanner.py
=======================
Dynamically scans a Python/Flask application to discover cryptographic
touchpoints. Uses:
  - Python's ast module to parse source files
  - Dependency analysis of requirements.txt / Pipfile.lock
  - Pattern matching for config files (nginx.conf, sshd_config, .env)

Returns a list of CryptoFinding dataclass objects.
"""

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("cbom.scanner")

# ──────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE BASE — maps detected patterns to crypto metadata
# ──────────────────────────────────────────────────────────────────────────────

# Library name → crypto metadata
LIBRARY_CRYPTO_MAP = {
    "PyJWT":          {"algorithm": "RS256/HS256 (JWT)",      "purpose": "JWT token signing/verification",       "vulnerable": True,  "risk": "HIGH"},
    "python-jose":    {"algorithm": "RS256/ES256 (JWT)",      "purpose": "JWT token signing/verification",       "vulnerable": True,  "risk": "HIGH"},
    "cryptography":   {"algorithm": "RSA/ECC/AES (multi)",    "purpose": "General-purpose crypto primitives",    "vulnerable": True,  "risk": "HIGH"},
    "pycryptodome":   {"algorithm": "RSA/AES (PyCryptodome)", "purpose": "Legacy crypto operations",             "vulnerable": True,  "risk": "HIGH"},
    "pycrypto":       {"algorithm": "RSA/AES (PyCrypto)",     "purpose": "Legacy crypto — deprecated",           "vulnerable": True,  "risk": "CRITICAL"},
    "paramiko":       {"algorithm": "RSA/ECDSA (SSH)",        "purpose": "SSH client/server connections",        "vulnerable": True,  "risk": "HIGH"},
    "pyOpenSSL":      {"algorithm": "RSA/ECC (TLS/SSL)",      "purpose": "TLS certificate and connection mgmt",  "vulnerable": True,  "risk": "HIGH"},
    "bcrypt":         {"algorithm": "bcrypt (symmetric)",     "purpose": "Password hashing",                     "vulnerable": False, "risk": "LOW"},
    "passlib":        {"algorithm": "bcrypt/Argon2 (hash)",   "purpose": "Password hashing abstraction",         "vulnerable": False, "risk": "LOW"},
    "itsdangerous":   {"algorithm": "HMAC-SHA1/256",          "purpose": "Session token / URL signing",          "vulnerable": False, "risk": "LOW"},
    "flask-login":    {"algorithm": "Session cookie (HMAC)",  "purpose": "User session management",              "vulnerable": False, "risk": "LOW"},
    "django":         {"algorithm": "PBKDF2/HMAC (built-in)", "purpose": "Django auth and session crypto",       "vulnerable": False, "risk": "LOW"},
    "sqlalchemy":     {"algorithm": "Varies (driver-level)",  "purpose": "DB connection — may use TLS",          "vulnerable": True,  "risk": "MEDIUM"},
    "requests":       {"algorithm": "TLS (via urllib3)",      "purpose": "HTTP client — TLS for all connections","vulnerable": True,  "risk": "MEDIUM"},
    "httpx":          {"algorithm": "TLS (via httpcore)",     "purpose": "Async HTTP client — TLS",              "vulnerable": True,  "risk": "MEDIUM"},
    "boto3":          {"algorithm": "AWS SigV4 (HMAC-SHA256)","purpose": "AWS API request signing",              "vulnerable": False, "risk": "LOW"},
    "azure-identity": {"algorithm": "RSA/ECC (MSAL tokens)",  "purpose": "Azure auth — RSA-signed JWTs",         "vulnerable": True,  "risk": "HIGH"},
    "google-auth":    {"algorithm": "RSA (GCP JWT signing)",  "purpose": "Google auth — RS256 service accounts", "vulnerable": True,  "risk": "HIGH"},
    "fabric":         {"algorithm": "RSA/ECDSA (SSH)",        "purpose": "SSH deployment automation",            "vulnerable": True,  "risk": "HIGH"},
    "cffi":           {"algorithm": "C bindings (varies)",    "purpose": "Low-level crypto bindings",            "vulnerable": True,  "risk": "MEDIUM"},
}

# AST import patterns → detected library
IMPORT_PATTERNS = {
    "jwt":                   "PyJWT",
    "jose":                  "python-jose",
    "cryptography":          "cryptography",
    "Crypto":                "pycryptodome",
    "crypto":                "pycrypto",
    "paramiko":              "paramiko",
    "OpenSSL":               "pyOpenSSL",
    "bcrypt":                "bcrypt",
    "passlib":               "passlib",
    "itsdangerous":          "itsdangerous",
    "flask_login":           "flask-login",
    "sqlalchemy":            "sqlalchemy",
    "requests":              "requests",
    "httpx":                 "httpx",
    "boto3":                 "boto3",
    "azure":                 "azure-identity",
    "google":                "google-auth",
    "fabric":                "fabric",
    "ssl":                   "ssl",      # stdlib TLS
    "hashlib":               "hashlib",  # stdlib hashing
    "hmac":                  "hmac",     # stdlib HMAC
}

# Specific API calls to detect — maps call string → metadata
CALL_PATTERNS = {
    r"rsa\.generate_private_key":     {"algorithm": "RSA",       "risk": "CRITICAL", "note": "RSA key generation detected"},
    r"ec\.generate_private_key":      {"algorithm": "ECC",       "risk": "HIGH",     "note": "ECC key generation detected"},
    r"rsa\.generate_key":             {"algorithm": "RSA-2048",  "risk": "CRITICAL", "note": "RSA key generation (PyCryptodome)"},
    r"PKCS1_OAEP":                    {"algorithm": "RSA-OAEP",  "risk": "CRITICAL", "note": "RSA OAEP encryption detected"},
    r"jwt\.encode.*RS256":            {"algorithm": "JWT RS256",  "risk": "HIGH",     "note": "JWT signed with RSA-2048"},
    r"jwt\.encode.*ES256":            {"algorithm": "JWT ES256",  "risk": "HIGH",     "note": "JWT signed with ECDSA P-256"},
    r"ssl\.SSLContext":               {"algorithm": "TLS/SSL",    "risk": "HIGH",     "note": "TLS context created — check cert algorithm"},
    r"ssl\.PROTOCOL_TLS":             {"algorithm": "TLS/SSL",    "risk": "HIGH",     "note": "TLS protocol used"},
    r"ECDSAKey":                      {"algorithm": "ECDSA",      "risk": "HIGH",     "note": "ECDSA SSH key via Paramiko"},
    r"RSAKey":                        {"algorithm": "RSA-SSH",    "risk": "CRITICAL", "note": "RSA SSH key via Paramiko"},
    r"hashlib\.md5":                  {"algorithm": "MD5",        "risk": "CRITICAL", "note": "MD5 is broken — do not use for security"},
    r"hashlib\.sha1":                 {"algorithm": "SHA-1",      "risk": "HIGH",     "note": "SHA-1 is deprecated for security use"},
    r"hashlib\.sha256":               {"algorithm": "SHA-256",    "risk": "LOW",      "note": "SHA-256 is quantum-resistant (Grover halves it to 128-bit)"},
    r"hashlib\.sha512":               {"algorithm": "SHA-512",    "risk": "LOW",      "note": "SHA-512 is quantum-resistant"},
    r"hmac\.new":                     {"algorithm": "HMAC-SHA*",  "risk": "LOW",      "note": "HMAC — safe if key >= 256 bits"},
    r"Fernet":                        {"algorithm": "AES-128-CBC","risk": "MEDIUM",   "note": "Fernet uses AES-128 — consider AES-256 for long-lived data"},
    r"ec\.SECP256R1":                 {"algorithm": "ECC P-256",  "risk": "HIGH",     "note": "NIST P-256 curve — vulnerable to quantum"},
    r"ec\.SECP384R1":                 {"algorithm": "ECC P-384",  "risk": "HIGH",     "note": "NIST P-384 curve — vulnerable to quantum"},
    r"load_cert_chain":               {"algorithm": "TLS cert",   "risk": "HIGH",     "note": "TLS certificate loaded — check key type in cert"},
    r"URLSafeTimedSerializer":        {"algorithm": "HMAC-SHA1",  "risk": "LOW",      "note": "itsdangerous uses HMAC — low quantum risk"},
    r"bcrypt\.hashpw":                {"algorithm": "bcrypt",     "risk": "LOW",      "note": "bcrypt password hashing — quantum-safe"},
}

# stdlib modules with crypto relevance
STDLIB_CRYPTO = {
    "ssl":     {"algorithm": "TLS (stdlib)",   "vulnerable": True,  "risk": "HIGH",   "purpose": "TLS/SSL socket wrapping"},
    "hashlib": {"algorithm": "SHA-*/MD5",      "vulnerable": False, "risk": "LOW",    "purpose": "Cryptographic hashing"},
    "hmac":    {"algorithm": "HMAC",           "vulnerable": False, "risk": "LOW",    "purpose": "Message authentication codes"},
    "secrets": {"algorithm": "CSPRNG",         "vulnerable": False, "risk": "LOW",    "purpose": "Cryptographically secure random numbers"},
}


# ──────────────────────────────────────────────────────────────────────────────
# DATACLASS — one finding per detected crypto touchpoint
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CryptoFinding:
    source:          str            # "ast_scan" | "dep_scan" | "config_scan"
    component:       str            # human-readable name
    location:        str            # file path (+ line number if available)
    algorithm:       str            # what crypto algorithm
    purpose:         str            # what it is used for
    vulnerable:      bool           # quantum-vulnerable?
    risk_level:      str            # CRITICAL / HIGH / MEDIUM / LOW
    pqc_replacement: str = ""       # suggested PQC drop-in
    qkd_needed:      bool = False
    data_shelf_life_years: int = 5
    migration_tier:  int  = 2
    notes:           str  = ""
    line_number:     Optional[int] = None


# ──────────────────────────────────────────────────────────────────────────────
# AST SCANNER — walks Python source files
# ──────────────────────────────────────────────────────────────────────────────

class ASTCryptoScanner(ast.NodeVisitor):
    """Walks a Python AST and records every crypto-relevant import and call."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[CryptoFinding] = []
        self._detected_libs: set = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._check_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        self._check_import(module, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_str = self._call_to_string(node)
        for pattern, meta in CALL_PATTERNS.items():
            if re.search(pattern, call_str):
                self._add_call_finding(call_str, meta, node.lineno)
        self.generic_visit(node)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _check_import(self, module_name: str, lineno: int):
        top = module_name.split(".")[0]
        lib = IMPORT_PATTERNS.get(top)
        if lib and lib not in self._detected_libs:
            self._detected_libs.add(lib)
            self._add_import_finding(lib, module_name, lineno)

    def _add_import_finding(self, lib: str, module: str, lineno: int):
        if lib in STDLIB_CRYPTO:
            meta = STDLIB_CRYPTO[lib]
            finding = CryptoFinding(
                source     = "ast_scan",
                component  = f"{lib} (stdlib) — import detected",
                location   = f"{self.filepath}:{lineno}",
                algorithm  = meta["algorithm"],
                purpose    = meta["purpose"],
                vulnerable = meta["vulnerable"],
                risk_level = meta["risk"],
                notes      = f"stdlib `{module}` imported",
                line_number= lineno,
            )
        elif lib in LIBRARY_CRYPTO_MAP:
            meta = LIBRARY_CRYPTO_MAP[lib]
            finding = CryptoFinding(
                source     = "ast_scan",
                component  = f"{lib} — import detected",
                location   = f"{self.filepath}:{lineno}",
                algorithm  = meta["algorithm"],
                purpose    = meta["purpose"],
                vulnerable = meta["vulnerable"],
                risk_level = meta["risk"],
                notes      = f"`{module}` imported",
                line_number= lineno,
            )
        else:
            return
        self.findings.append(finding)
        logger.debug("AST import finding: %s at %s:%s", lib, self.filepath, lineno)

    def _add_call_finding(self, call_str: str, meta: dict, lineno: int):
        finding = CryptoFinding(
            source     = "ast_scan",
            component  = f"API call: {call_str[:60]}",
            location   = f"{self.filepath}:{lineno}",
            algorithm  = meta["algorithm"],
            purpose    = "Detected via source code pattern match",
            vulnerable = meta["risk"] in ("CRITICAL", "HIGH"),
            risk_level = meta["risk"],
            notes      = meta["note"],
            line_number= lineno,
        )
        self.findings.append(finding)
        logger.debug("AST call finding: %s at line %s", call_str[:40], lineno)

    @staticmethod
    def _call_to_string(node: ast.Call) -> str:
        """Convert a Call node to a dotted string for pattern matching."""
        try:
            return ast.unparse(node)
        except Exception:
            return ""


# ──────────────────────────────────────────────────────────────────────────────
# DEPENDENCY SCANNER — parses requirements.txt / Pipfile.lock
# ──────────────────────────────────────────────────────────────────────────────

class DependencyScanner:
    """Reads requirements.txt and flags crypto-relevant libraries."""

    def __init__(self, dep_file: Path):
        self.dep_file = dep_file
        self.findings: List[CryptoFinding] = []

    def scan(self) -> List[CryptoFinding]:
        if not self.dep_file.exists():
            logger.warning("Dependency file not found: %s", self.dep_file)
            return []

        logger.info("Scanning dependencies: %s", self.dep_file)
        with open(self.dep_file) as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = re.split(r"[>=<!~\[]", line)[0].strip()
            self._check_package(pkg_name, line)

        return self.findings

    def _check_package(self, pkg_name: str, raw_line: str):
        # Normalise: PyJWT → pyjwt, pycryptodome → pycryptodome
        normalised = pkg_name.lower().replace("-", "").replace("_", "")
        for lib_key, meta in LIBRARY_CRYPTO_MAP.items():
            if lib_key.lower().replace("-", "").replace("_", "") == normalised:
                finding = CryptoFinding(
                    source     = "dep_scan",
                    component  = f"{pkg_name} (dependency)",
                    location   = str(self.dep_file),
                    algorithm  = meta["algorithm"],
                    purpose    = meta["purpose"],
                    vulnerable = meta["vulnerable"],
                    risk_level = meta["risk"],
                    notes      = f"Found in requirements: `{raw_line.strip()}`",
                )
                self.findings.append(finding)
                logger.debug("Dep finding: %s", pkg_name)
                return


# ──────────────────────────────────────────────────────────────────────────────
# CONFIG FILE SCANNER — nginx.conf, sshd_config, .env, docker-compose
# ──────────────────────────────────────────────────────────────────────────────

CONFIG_PATTERNS = [
    (r"ssl_certificate",      "TLS certificate",     "TLS/SSL", "HIGH",     True,  "nginx TLS cert — check algorithm"),
    (r"ssl_protocols\s+.*TLSv1\b", "TLS 1.0 active","TLS 1.0", "CRITICAL", True,  "TLS 1.0 is deprecated — disable immediately"),
    (r"ssl_protocols\s+.*TLSv1\.1","TLS 1.1 active", "TLS 1.1","CRITICAL", True,  "TLS 1.1 is deprecated — disable immediately"),
    (r"HostKey.*rsa",         "SSH RSA host key",    "RSA-SSH", "CRITICAL", True,  "RSA SSH host key in sshd_config"),
    (r"HostKey.*ecdsa",       "SSH ECDSA host key",  "ECDSA",   "HIGH",     True,  "ECDSA SSH host key in sshd_config"),
    (r"RSA_PRIVATE_KEY",      "RSA private key env", "RSA",     "CRITICAL", True,  "RSA private key stored in environment variable"),
    (r"ECDSA_PRIVATE_KEY",    "ECDSA key env var",   "ECDSA",   "HIGH",     True,  "ECDSA private key in env var"),
    (r"JWT_SECRET.*=",        "JWT secret env var",  "JWT/HMAC","LOW",      False, "JWT secret in env — check if using RS256 or HS256"),
    (r"SSL_CERT",             "TLS cert env var",    "TLS/SSL", "HIGH",     True,  "TLS certificate path in environment"),
]

class ConfigScanner:
    """Scans config and env files for crypto-relevant settings."""

    CONFIG_FILENAMES = {
        "nginx.conf", "nginx.conf.d", "sshd_config", ".env",
        "docker-compose.yml", "docker-compose.yaml",
        ".env.production", ".env.example",
    }

    def __init__(self, root: Path):
        self.root = root
        self.findings: List[CryptoFinding] = []

    def scan(self) -> List[CryptoFinding]:
        for path in self.root.rglob("*"):
            if path.is_file() and path.name in self.CONFIG_FILENAMES:
                self._scan_file(path)
        return self.findings

    def _scan_file(self, path: Path):
        logger.info("Scanning config file: %s", path)
        try:
            content = path.read_text(errors="ignore")
        except Exception as e:
            logger.warning("Could not read %s: %s", path, e)
            return

        for (pattern, component, algo, risk, vuln, note) in CONFIG_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                finding = CryptoFinding(
                    source     = "config_scan",
                    component  = component,
                    location   = str(path),
                    algorithm  = algo,
                    purpose    = "Configuration-level crypto setting",
                    vulnerable = vuln,
                    risk_level = risk,
                    notes      = note,
                )
                self.findings.append(finding)
                logger.debug("Config finding: %s in %s", component, path)


# ──────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER — orchestrates all sub-scanners and deduplicates
# ──────────────────────────────────────────────────────────────────────────────

class CryptoScanner:
    """
    Top-level scanner. Point it at a project root and it returns
    all CryptoFinding objects discovered across all scan methods.
    """

    def __init__(self, project_root: str):
        self.root = Path(project_root).resolve()
        self.findings: List[CryptoFinding] = []

    def run(self) -> List[CryptoFinding]:
        logger.info("Starting CBOM scan on: %s", self.root)

        # 1. AST scan all Python files
        py_files = list(self.root.rglob("*.py"))
        logger.info("Found %d Python files to scan", len(py_files))
        for py_file in py_files:
            self._ast_scan(py_file)

        # 2. Dependency scan
        for dep_file in ["requirements.txt", "requirements-dev.txt", "Pipfile"]:
            dep_path = self.root / dep_file
            dep_findings = DependencyScanner(dep_path).scan()
            self.findings.extend(dep_findings)

        # 3. Config scan
        config_findings = ConfigScanner(self.root).scan()
        self.findings.extend(config_findings)

        # 4. Deduplicate (same component + location)
        before = len(self.findings)
        self.findings = self._deduplicate(self.findings)
        logger.info("Scan complete. %d findings (%d after dedup)", before, len(self.findings))

        # 5. Enrich with PQC replacements and migration tiers
        self.findings = [self._enrich(f) for f in self.findings]

        return self.findings

    def _ast_scan(self, filepath: Path):
        try:
            source = filepath.read_text(errors="ignore")
            tree   = ast.parse(source)
            scanner = ASTCryptoScanner(str(filepath.relative_to(self.root)))
            scanner.visit(tree)
            self.findings.extend(scanner.findings)
        except SyntaxError as e:
            logger.warning("Syntax error in %s: %s", filepath, e)
        except Exception as e:
            logger.warning("Could not parse %s: %s", filepath, e)

    @staticmethod
    def _deduplicate(findings: List[CryptoFinding]) -> List[CryptoFinding]:
        seen   = set()
        unique = []
        for f in findings:
            key = (f.component, f.algorithm, f.location.split(":")[0])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _enrich(f: CryptoFinding) -> CryptoFinding:
        """Fill in PQC replacement suggestions and migration tiers."""
        algo = f.algorithm.upper()

        if "RSA" in algo:
            f.pqc_replacement    = "CRYSTALS-Kyber (key enc) / ML-DSA (signatures) — NIST FIPS 203/204"
            f.data_shelf_life_years = 10
            f.migration_tier     = 1
            if "OAEP" in algo or "ENCRYPT" in f.notes.upper():
                f.qkd_needed = True
                f.data_shelf_life_years = 20

        elif "ECC" in algo or "ECDSA" in algo or "ECDH" in algo or "P-256" in algo or "P-384" in algo:
            f.pqc_replacement    = "ML-DSA (Dilithium) for signatures / ML-KEM (Kyber) for key exchange"
            f.data_shelf_life_years = 10
            f.migration_tier     = 1

        elif "JWT" in algo and ("RS" in algo or "ES" in algo):
            f.pqc_replacement    = "ML-DSA (Dilithium) — drop-in for RS256/ES256"
            f.data_shelf_life_years = 2
            f.migration_tier     = 2

        elif "TLS" in algo or "SSL" in algo:
            f.pqc_replacement    = "X25519Kyber768 hybrid KEM (TLS 1.3) — supported in OpenSSL 3.2+"
            f.data_shelf_life_years = 15
            f.migration_tier     = 1

        elif "SSH" in algo:
            f.pqc_replacement    = "sntrup761x25519 hybrid (OpenSSH 9.x built-in)"
            f.data_shelf_life_years = 10
            f.migration_tier     = 1

        elif "BCRYPT" in algo or "PBKDF2" in algo or "ARGON" in algo:
            f.pqc_replacement    = "No change needed — symmetric/hash-based, quantum-safe"
            f.migration_tier     = 4
            f.vulnerable         = False

        elif "HMAC" in algo:
            f.pqc_replacement    = "No change needed — HMAC-SHA256 is quantum-safe"
            f.migration_tier     = 4
            f.vulnerable         = False

        elif "SHA-256" in algo or "SHA-512" in algo:
            f.pqc_replacement    = "No change needed — SHA-256/512 are quantum-resistant"
            f.migration_tier     = 4
            f.vulnerable         = False

        elif "MD5" in algo:
            f.pqc_replacement    = "Replace with SHA-256 immediately — MD5 is broken classically"
            f.migration_tier     = 1
            f.risk_level         = "CRITICAL"

        elif "AES-128" in algo:
            f.pqc_replacement    = "Upgrade to AES-256 (Grover halves key strength to 64-bit)"
            f.migration_tier     = 3

        else:
            f.pqc_replacement    = "Review manually — algorithm type not in PQC map"
            f.migration_tier     = 3

        return f
