"""
sample_flask_app/app.py
A realistic Flask application that uses multiple cryptographic primitives.
This is the TARGET that cbom_audit.py will scan.
"""

from flask import Flask, request, jsonify, session
from flask_login import LoginManager, login_user
import jwt                          # PyJWT  — RS256 signing
import ssl                          # TLS context creation
import hashlib                      # SHA-256 direct usage
import hmac                         # HMAC signing
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet           # symmetric encryption
from Crypto.PublicKey import RSA as CryptoRSA   # PyCryptodome legacy
from Crypto.Cipher import PKCS1_OAEP
import bcrypt                                    # password hashing
import paramiko                                  # SSH client
from itsdangerous import URLSafeTimedSerializer  # session signing
import base64
import os
from pathlib import Path

# ── Get the directory of this script ─────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# ── JWT signing with RS256 (RSA-2048) ────────────────────────────────────────
PRIVATE_KEY_PATH = SCRIPT_DIR / "keys" / "private_rsa2048.pem"
PUBLIC_KEY_PATH  = SCRIPT_DIR / "keys" / "public_rsa2048.pem"

def generate_jwt_token(user_id: int) -> str:
    """Sign a JWT with RS256 (RSA-2048 private key)."""
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read()
    token = jwt.encode(
        {"sub": user_id, "alg": "RS256"},
        private_key,
        algorithm="RS256"
    )
    return token

def verify_jwt_token(token: str) -> dict:
    """Verify a JWT signed with RS256."""
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = f.read()
    return jwt.decode(token, public_key, algorithms=["RS256"])

# ── RSA key generation (cryptography library) ────────────────────────────────
def generate_rsa_keypair():
    """Generate a 2048-bit RSA keypair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# ── ECC key (NIST P-256) ─────────────────────────────────────────────────────
def generate_ecc_key():
    """Generate an ECC key on the P-256 (secp256r1) curve."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    return private_key

# ── RSA encryption with OAEP (PyCryptodome) ──────────────────────────────────
def encrypt_field_rsa(data: bytes, pub_key_pem: bytes) -> bytes:
    """Encrypt a database field using RSA-OAEP (PyCryptodome)."""
    key = CryptoRSA.import_key(pub_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

# ── Fernet (AES-128-CBC) symmetric encryption ────────────────────────────────
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

def encrypt_backup_data(data: bytes) -> bytes:
    return fernet.encrypt(data)

# ── Password hashing with bcrypt ─────────────────────────────────────────────
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# ── SHA-256 direct usage ──────────────────────────────────────────────────────
def compute_document_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

# ── HMAC-SHA256 for session cookies ──────────────────────────────────────────
def sign_session_data(data: str, secret: bytes) -> str:
    mac = hmac.new(secret, data.encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()

# ── TLS context creation ─────────────────────────────────────────────────────
def create_tls_context() -> ssl.SSLContext:
    """Create a TLS 1.3 server context with RSA certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        str(SCRIPT_DIR / "certs" / "server.crt"),
        str(SCRIPT_DIR / "certs" / "server.key")
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx

# ── SSH via Paramiko (ECDSA key) ──────────────────────────────────────────────
def connect_ssh(host: str, username: str, key_path: str):
    """Connect to a server via SSH using an ECDSA key."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.ECDSAKey.from_private_key_file(key_path)
    client.connect(host, username=username, pkey=key)
    return client

# ── ECDSA signing (cryptography library) ─────────────────────────────────────
def sign_artifact(data: bytes, private_key) -> bytes:
    """Sign a deployment artifact with ECDSA."""
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

# ── itsdangerous URLSafeTimedSerializer ──────────────────────────────────────
serializer = URLSafeTimedSerializer(app.secret_key)

def create_password_reset_token(email: str) -> str:
    return serializer.dumps(email, salt="password-reset")

# ── Flask routes ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({"message": "CBOM Sample App - Use /login or /health"})

@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    token    = generate_jwt_token(data["user_id"])
    return jsonify({"token": token})

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    ctx = create_tls_context()
    app.run(ssl_context=ctx, port=5000)
