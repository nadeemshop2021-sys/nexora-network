import os
import json
import base64
from hashlib import sha256
from datetime import datetime, timezone
from threading import Lock

import psycopg2
from psycopg2.extras import Json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
Ed25519PrivateKey,
Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(name)
CORS(app)

DATABASE_URL = os.environ.get("DATABASE_URL")
DIFFICULTY = 3
lock = Lock()

if not DATABASE_URL:
raise Runtime Error("DATABASE_URL environment variable is missing")

def get_db():
return psycopg2.connect(DATABASE_URL)

def now():
return datetime.now(timezone.utc).isoformat()

def canonical_json(data):
return json.dumps(
data, sort_keys=True, separators=(",", ":")
).encode("utf-8")

def wallet_address(public_key_hex):
return "NXR" + sha256(bytes.fromhex(public_key_hex)).hexdigest()[:40].upper()

def create_wallet():
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

public_hex = public_bytes.hex()

return {
    "address": wallet_address(public_hex),
    "public_key": public_hex,
    "private_key": private_bytes.hex(),
    "warning": (
        "Save your private key securely. It cannot be recovered. "
        "Never share it or upload it to GitHub."
    ),
}

def transaction_message(tx):
return canonical_json({
"sender": tx["sender"],
"recipient": tx["recipient"],
"amount": tx["amount"],
"nonce": tx["nonce"],
})

def verify_signature(tx):
try:
public_hex = tx["public_key"]
public_bytes = bytes.fromhex(public_hex)

    if wallet_address(public_hex) != tx["sender"]:
        return False

    public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
    signature = base64.b64decode(tx["signature"], validate=True)
    public_key.verify(signature, transaction_message(tx))
    return True
except Exception:
    return False

def block_payload(block):
return {
"index": block["index"],
"timestamp": block["timestamp"],
"transactions": block["transactions"],
"previous_hash": block["previous_hash"],
"nonce": block["nonce"],
}

def block_hash(block):
return sha256(canonical_json(block_payload(block))).hexdigest()

def create_genesis():
block = {
"index": 0,
"timestamp": now(),
"transactions": [],
"previous_hash": "0" * 64,
"nonce": 0,
}
block["hash"] = block_hash(block)
return block

def save_block(cur, block):
cur.execute(
"""
INSERT INTO nexora_blocks
(block_index, block_timestamp, transactions,
previous_hash, nonce, block_hash)
VALUES (%s, %s, %s, %s, %s, %s)
""",
(
block["index"],
block["timestamp"],
Json(block["transactions"]),
block["previous_hash"],
block["nonce"],
block["hash"],
),
)

def init_db():
global chain

conn = get_db()
try:
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS nexora_blocks (
                    block_index BIGINT PRIMARY KEY,
                    block_timestamp TEXT NOT NULL,
                    transactions JSONB NOT NULL,
                    previous_hash TEXT NOT NULL,
                    nonce BIGINT NOT NULL,
                    block_hash TEXT NOT NULL UNIQUE
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS nexora_nonces (
                    wallet_address TEXT PRIMARY KEY,
                    next_nonce BIGINT NOT NULL DEFAULT 0
                )
            """)
            cur.execute("""
                SELECT block_index, block_timestamp,
                       transactions, previous_hash,
                       nonce, block_hash
                FROM nexora_blocks
                ORDER BY block_index ASC
            """)
            rows = cur.fetchall()

            if not rows:
                genesis = create_genesis()
                save_block(cur, genesis)
                chain = [genesis]
            else:
                chain = []
                for row in rows:
                    transactions = row[2]
                    if isinstance(transactions, str):
                        transactions = json.loads(transactions)
                    chain.append({
                        "index": row[0],
                        "timestamp": row[1],
                        "transactions": transactions,
                        "previous_hash": row[3],
                        "nonce": row[4],
                        "hash": row[5],
                    })
finally:
    conn.close()

chain = []
init_db()

def all_transactions():
return [
tx
for block in chain
for tx in block["transactions"]
]

def calculate_balance(address):
balance = 0.0

for tx in all_transactions():
    if tx.get("recipient") == address:
        balance += float(tx["amount"])
    if tx.get("sender") == address:
        balance -= float(tx["amount"])

return round(balance, 8)

def next_nonce(address):
conn = get_db()
try:
with conn:
with conn.cursor() as cur:
cur.execute("""
INSERT INTO nexora_nonces (wallet_address, next_nonce)
VALUES (%s, 0)
ON CONFLICT (wallet_address) DO NOTHING
""", (address,))
cur.execute("""
SELECT next_nonce FROM nexora_nonces
WHERE wallet_address = %s
""", (address,))
row = cur.fetchone()
return row[0]
finally:
conn.close()

@app.get("/")
def home():
return jsonify({
"name": "NEXORA Network",
"symbol": "NXR",
"status": "online",
"version": "4.0-wallet-prototype",
"storage": "PostgreSQL",
"test_network": True,
})

@app.get("/health")
def health():
with lock:
return jsonify({
"status": "online",
"blocks": len(chain),
"storage": "PostgreSQL",
})

@app.get("/chain")
def get_chain():
with lock:
return jsonify({
"length": len(chain),
"difficulty": DIFFICULTY,
"chain": chain,
})

@app.get("/verify")
def verify_chain():
with lock:
for i, block in enumerate(chain):
if block.get("hash") != block_hash(block):
return jsonify({
"valid": False,
"error": f"Invalid hash at block {i}",
})

        if i == 0:
            if block["previous_hash"] != "0" * 64:
                return jsonify({
                    "valid": False,
                    "error": "Invalid genesis",
                })
        else:
            if block["index"] != i:
                return jsonify({
                    "valid": False,
                    "error": f"Invalid index at block {i}",
                })
            if block["previous_hash"] != chain[i - 1]["hash"]:
                return jsonify({
                    "valid": False,
                    "error": f"Broken link at block {i}",
                })
            if not block["hash"].startswith("0" * DIFFICULTY):
                return jsonify({
                    "valid": False,
                    "error": f"Invalid proof of work at block {i}",
                })

    return jsonify({
        "valid": True,
        "blocks": len(chain),
        "message": "NEXORA chain is valid",
    })

@app.post("/wallet/create")
def wallet_create():
# The private key is generated for the user and is never stored by this API.
return jsonify(create_wallet()), 201

@app.get("/wallet/<address>/balance")
def wallet_balance(address):
with lock:
return jsonify({
"address": address,
"balance": calculate_balance(address),
"unit": "test NXR",
"test_network": True,
})

@app.get("/wallet/<address>/nonce")
def wallet_nonce(address):
return jsonify({
"address": address,
"nonce": next_nonce(address),
})

@app.post("/transaction")
def create_transaction():
data = request.get_json(silent=True) or {}

required = [
    "sender", "recipient", "amount",
    "public_key", "signature", "nonce",
]
if any(key not in data for key in required):
    return jsonify({
        "error": "Required fields: " + ", ".join(required)
    }), 400

try:
    amount = float(data["amount"])
    nonce = int(data["nonce"])
    if amount <= 0 or amount > 1_000_000_000:
        raise ValueError()
    if nonce < 0:
        raise ValueError()
except (TypeError, ValueError, OverflowError):
    return jsonify({"error": "Invalid amount or nonce"}), 400

tx = {
    "sender": str(data["sender"]),
    "recipient": str(data["recipient"]),
    "amount": amount,
    "public_key": str(data["public_key"]),
    "signature": str(data["signature"]),
    "nonce": nonce,
}

if len(tx["recipient"]) > 100:
    return jsonify({"error": "Invalid recipient"}), 400

if not verify_signature(tx):
    return jsonify({"error": "Invalid wallet address or signature"}), 400

with lock:
    expected_nonce = next_nonce(tx["sender"])
    if tx["nonce"] != expected_nonce:
        return jsonify({
            "error": "Incorrect nonce",
            "expected_nonce": expected_nonce,
        }), 400

    balance = calculate_balance(tx["sender"])
    if balance < amount:
        return jsonify({
            "error": "Insufficient test NXR balance",
            "balance": balance,
        }), 400

    # Transactions are held in a server-side pending pool until mined.
    pending = app.config.setdefault("pending_transactions", [])
    if any(p["sender"] == tx["sender"] for p in pending):
        return jsonify({
            "error": "This wallet already has a pending transaction"
        }), 409

    pending.append(tx)

    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE nexora_nonces
                    SET next_nonce = next_nonce + 1
                    WHERE wallet_address = %s AND next_nonce = %s
                """, (tx["sender"], tx["nonce"]))
                if cur.rowcount != 1:
                    raise ValueError("Nonce conflict")
    except Exception:
        pending.remove(tx)
        return jsonify({"error": "Could not save transaction nonce"}), 500
    finally:
        conn.close()

return jsonify({
    "message": "Transaction accepted into pending pool",
    "transaction": tx,
    "note": "Test network only; transaction is not yet in a block.",
}), 202

@app.post("/mine")
def mine_block():
with lock:
previous = chain[-1]
pending = app.config.setdefault("pending_transactions", [])

    block = {
        "index": len(chain),
        "timestamp": now(),
        "transactions": list(pending),
        "previous_hash": previous["hash"],
        "nonce": 0,
    }

    target = "0" * DIFFICULTY
    while True:
        digest = block_hash(block)
        if digest.startswith(target):
            break
        block["nonce"] += 1

    block["hash"] = digest

    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                save_block(cur, block)
    except Exception:
        return jsonify({"error": "Could not save block"}), 500
    finally:
        conn.close()

    chain.append(block)
    pending.clear()

    return jsonify({
        "message": "NEXORA test block saved",
        "block": block,
        "length": len(chain),
    }), 201

@app.get("/transactions/pending")
def pending_transactions():
with lock:
return jsonify({
"pending": app.config.setdefault("pending_transactions", []),
"count": len(app.config.setdefault("pending_transactions", [])),
})

@app.errorhandler(404)
def not_found(error):
return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(error):
app.logger.exception("NEXORA server error")
return jsonify({"error": "Internal server error"}), 500
