import os
import json
import base64
import re
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from datetime import datetime, timezone
from threading import RLock

import psycopg2
from psycopg2.extras import Json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ.get("DATABASE_URL")

DIFFICULTY = 3
BLOCK_REWARD = Decimal("100")
MAX_SUPPLY = Decimal("21000000")
MAX_AMOUNT = Decimal("1000000000")
MAX_DECIMALS = Decimal("0.00000001")

lock = RLock()
chain = []
pending_transactions = []

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is missing")


# ==================================================
# DATABASE
# ==================================================

def get_db():
    return psycopg2.connect(DATABASE_URL)


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def init_db():
    global chain, pending_transactions

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
                    CREATE TABLE IF NOT EXISTS nexora_pending (
                        sender TEXT PRIMARY KEY,
                        transaction JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)

                cur.execute("""
                    SELECT block_index, block_timestamp,
                           transactions, previous_hash,
                           nonce, block_hash
                    FROM nexora_blocks
                    ORDER BY block_index
                """)

                rows = cur.fetchall()

                if not rows:
                    genesis = create_genesis()
                    save_block(cur, genesis)
                    chain = [genesis]
                else:
                    loaded = []

                    for row in rows:
                        transactions = row[2]

                        if isinstance(transactions, str):
                            transactions = json.loads(transactions)

                        loaded.append({
                            "index": row[0],
                            "timestamp": row[1],
                            "transactions": transactions,
                            "previous_hash": row[3],
                            "nonce": row[4],
                            "hash": row[5],
                        })

                    chain = loaded

                cur.execute("""
                    SELECT transaction
                    FROM nexora_pending
                    ORDER BY created_at, sender
                """)

                pending_transactions = []

                for row in cur.fetchall():
                    tx = row[0]

                    if isinstance(tx, str):
                        tx = json.loads(tx)

                    pending_transactions.append(tx)

    finally:
        conn.close()


# ==================================================
# WALLET / ADDRESS
# ==================================================

def valid_address(address):
    return (
        isinstance(address, str)
        and re.fullmatch(r"NXR[0-9A-F]{40}", address) is not None
    )


def wallet_address(public_key_hex):
    return (
        "NXR"
        + sha256(bytes.fromhex(public_key_hex))
        .hexdigest()[:40]
        .upper()
    )


# ==================================================
# AMOUNT
# ==================================================

def as_amount(value):
    if isinstance(value, bool):
        raise ValueError("Invalid amount")

    amount = Decimal(str(value))

    if not amount.is_finite():
        raise ValueError("Invalid amount")

    if amount <= 0 or amount > MAX_AMOUNT:
        raise ValueError("Amount out of range")

    if amount != amount.quantize(MAX_DECIMALS):
        raise ValueError("Maximum 8 decimal places allowed")

    return format(amount, "f")


def amount_decimal(value):
    amount = Decimal(str(value))

    if not amount.is_finite():
        raise ValueError("Invalid amount")

    return amount


# ==================================================
# TRANSACTION SIGNATURE
# ==================================================

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

        if not isinstance(public_hex, str):
            return False

        if re.fullmatch(r"[0-9a-fA-F]{64}", public_hex) is None:
            return False

        public_bytes = bytes.fromhex(public_hex)

        if len(public_bytes) != 32:
            return False

        if wallet_address(public_hex) != tx["sender"]:
            return False

        signature = base64.b64decode(
            tx["signature"],
            validate=True,
        )

        if len(signature) != 64:
            return False

        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

        public_key.verify(
            signature,
            transaction_message(tx),
        )

        return True

    except Exception:
        return False


def validate_normal_transaction(tx):
    if not isinstance(tx, dict):
        return False, "Transaction must be an object"

    required = {
        "sender", "recipient", "amount",
        "public_key", "signature", "nonce"
    }

    if not required.issubset(tx):
        return False, "Missing transaction fields"

    if not valid_address(tx["sender"]):
        return False, "Invalid sender address"

    if not valid_address(tx["recipient"]):
        return False, "Invalid recipient address"

    try:
        amount = Decimal(as_amount(tx["amount"]))

        if isinstance(tx["nonce"], bool):
            return False, "Invalid nonce"

        nonce = tx["nonce"]

        if not isinstance(nonce, int) or nonce < 0:
            return False, "Invalid nonce"

        if not verify_signature(tx):
            return False, "Invalid signature"

        if amount <= 0:
            return False, "Amount must be positive"

    except (ValueError, TypeError, InvalidOperation):
        return False, "Invalid amount or nonce"

    return True, ""


# ==================================================
# BLOCKCHAIN
# ==================================================

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
    cur.execute("""
        INSERT INTO nexora_blocks (
            block_index, block_timestamp, transactions,
            previous_hash, nonce, block_hash
        )
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        block["index"],
        block["timestamp"],
        Json(block["transactions"]),
        block["previous_hash"],
        block["nonce"],
        block["hash"],
    ))


# ==================================================
# BALANCE / REPLAY
# ==================================================

def replay_chain(blocks):
    """
    Replay the blockchain and validate:
    - block hashes and links
    - proof of work
    - transaction signatures
    - sequential nonces
    - balances and double-spending
    - reward rules and supply
    """
    balances = {}
    nonces = {}
    total_mined = Decimal("0")

    if not blocks:
        return False, "Blockchain is empty", balances, nonces, total_mined

    for i, block in enumerate(blocks):
        if block.get("hash") != block_hash(block):
            return False, f"Invalid hash at block {i}", balances, nonces, total_mined

        if block.get("index") != i:
            return False, f"Invalid index at block {i}", balances, nonces, total_mined

        if i == 0:
            if block.get("previous_hash") != "0" * 64:
                return False, "Invalid genesis link", balances, nonces, total_mined

            if block.get("transactions") != []:
                return False, "Genesis transactions not allowed", balances, nonces, total_mined

            continue

        if block.get("previous_hash") != blocks[i - 1].get("hash"):
            return False, f"Broken link at block {i}", balances, nonces, total_mined

        if not block["hash"].startswith("0" * DIFFICULTY):
            return False, f"Invalid proof of work at block {i}", balances, nonces, total_mined

        transactions = block.get("transactions")

        if not isinstance(transactions, list):
            return False, f"Invalid transactions list at block {i}", balances, nonces, total_mined

        rewards = [
            tx for tx in transactions
            if isinstance(tx, dict) and tx.get("type") == "REWARD"
        ]

        if len(rewards) != 1:
            return False, f"Block {i} must have exactly one reward", balances, nonces, total_mined

        normal_txs = [
            tx for tx in transactions
            if not (isinstance(tx, dict) and tx.get("type") == "REWARD")
        ]

        # Validate normal transactions in block order.
        for tx in normal_txs:
            valid, reason = validate_normal_transaction(tx)

            if not valid:
                return False, f"Invalid transaction at block {i}: {reason}", balances, nonces, total_mined

            sender = tx["sender"]
            recipient = tx["recipient"]
            amount = Decimal(tx["amount"])
            nonce = tx["nonce"]

            expected_nonce = nonces.get(sender, 0)

            if nonce != expected_nonce:
                return False, f"Invalid nonce at block {i}", balances, nonces, total_mined

            if balances.get(sender, Decimal("0")) < amount:
                return False, f"Insufficient balance at block {i}", balances, nonces, total_mined

            balances[sender] = balances.get(sender, Decimal("0")) - amount
            balances[recipient] = balances.get(recipient, Decimal("0")) + amount
            nonces[sender] = expected_nonce + 1

        reward = rewards[0]

        try:
            reward_amount = Decimal(str(reward["amount"]))
        except Exception:
            return False, f"Invalid reward at block {i}", balances, nonces, total_mined

        if (
            reward.get("sender") != "NETWORK"
            or not valid_address(reward.get("recipient"))
            or reward_amount != BLOCK_REWARD
            or set(reward.keys()) != {"type", "sender", "recipient", "amount"}
        ):
            return False, f"Invalid reward at block {i}", balances, nonces, total_mined

        if total_mined + reward_amount > MAX_SUPPLY:
            return False, "Maximum reward supply exceeded", balances, nonces, total_mined

        total_mined += reward_amount
        miner = reward["recipient"]
        balances[miner] = balances.get(miner, Decimal("0")) + reward_amount

    return True, "", balances, nonces, total_mined


def all_transactions():
    return [
        tx
        for block in chain
        for tx in block.get("transactions", [])
    ]


def calculate_balance(address):
    valid, error, balances, _, _ = replay_chain(chain)

    if not valid:
        raise RuntimeError("Blockchain validation failed: " + error)

    return format(balances.get(address, Decimal("0")), "f")


def total_rewards():
    total = Decimal("0")

    for tx in all_transactions():
        if isinstance(tx, dict) and tx.get("type") == "REWARD":
            total += Decimal(str(tx["amount"]))

    return total


def confirmed_nonce(address):
    valid, error, _, nonces, _ = replay_chain(chain)

    if not valid:
        raise RuntimeError("Blockchain validation failed: " + error)

    return nonces.get(address, 0)


def pending_nonce(address):
    nonce = confirmed_nonce(address)

    for tx in pending_transactions:
        if tx.get("sender") == address:
            nonce += 1

    return nonce


def pending_balance(address):
    balance = Decimal(calculate_balance(address))

    for tx in pending_transactions:
        amount = Decimal(tx["amount"])

        if tx["sender"] == address:
            balance -= amount

        if tx["recipient"] == address:
            balance += amount

    return balance


# Load blockchain and pending transactions.
init_db()


# ==================================================
# ROUTES: HOME / HEALTH
# ==================================================

@app.get("/")
def home():
    return jsonify({
        "name": "NEXORA Network",
        "symbol": "NXR",
        "status": "online",
        "version": "6.0-secure-testnet",
        "storage": "PostgreSQL",
        "test_network": True,
        "block_reward": str(BLOCK_REWARD),
        "max_supply": str(MAX_SUPPLY),
    })


@app.get("/health")
def health():
    with lock:
        valid, error, _, _, _ = replay_chain(chain)

        return jsonify({
            "status": "online" if valid else "error",
            "blocks": len(chain),
            "storage": "PostgreSQL",
            "test_network": True,
            "chain_valid": valid,
            "error": error if not valid else None,
        }), (200 if valid else 500)


# ==================================================
# ROUTES: CHAIN / VERIFY
# ==================================================

@app.get("/chain")
def get_chain():
    with lock:
        return jsonify({
            "length": len(chain),
            "difficulty": DIFFICULTY,
            "block_reward": str(BLOCK_REWARD),
            "chain": chain,
        })


@app.get("/verify")
def verify_chain():
    with lock:
        valid, error, _, _, mined = replay_chain(chain)

        if not valid:
            return jsonify({
                "valid": False,
                "error": error,
            }), 200

        return jsonify({
            "valid": True,
            "blocks": len(chain),
            "total_mined_rewards": format(mined, "f"),
            "message": "NEXORA chain is valid",
        })


# ==================================================
# ROUTES: WALLET
# ==================================================

@app.post("/wallet/create")
def wallet_create():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

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

    return jsonify({
        "address": wallet_address(public_hex),
        "public_key": public_hex,
        "private_key": private_bytes.hex(),
        "warning": "Save your private key securely. Never share it.",
    }), 201


@app.get("/wallet/<address>/balance")
def wallet_balance(address):
    if not valid_address(address):
        return jsonify({"error": "Invalid wallet address"}), 400

    with lock:
        try:
            balance = calculate_balance(address)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503

        return jsonify({
            "address": address,
            "balance": balance,
            "unit": "test NXR",
            "test_network": True,
        })


@app.get("/wallet/<address>/nonce")
def wallet_nonce(address):
    if not valid_address(address):
        return jsonify({"error": "Invalid wallet address"}), 400

    with lock:
        try:
            nonce = pending_nonce(address)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503

        return jsonify({
            "address": address,
            "nonce": nonce,
        })


# ==================================================
# PERSIST PENDING TRANSACTIONS
# ==================================================

def persist_pending(tx):
    conn = get_db()

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO nexora_pending (sender, transaction)
                    VALUES (%s, %s)
                    ON CONFLICT (sender)
                    DO UPDATE SET
                        transaction = EXCLUDED.transaction,
                        created_at = NOW()
                """, (tx["sender"], Json(tx)))
    finally:
        conn.close()


def delete_pending(sender):
    conn = get_db()

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM nexora_pending WHERE sender = %s",
                    (sender,),
                )
    finally:
        conn.close()


# ==================================================
# ROUTE: CREATE TRANSACTION
# ==================================================

@app.post("/transaction")
def create_transaction():
    data = request.get_json(silent=True) or {}

    required = [
        "sender", "recipient", "amount",
        "public_key", "signature", "nonce",
    ]

    if any(key not in data for key in required):
        return jsonify({
            "error": "Required fields: " + ", ".join(required),
        }), 400

    try:
        amount = as_amount(data["amount"])
        nonce = data["nonce"]

        if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
            raise ValueError("Invalid nonce")

    except (TypeError, ValueError, InvalidOperation):
        return jsonify({"error": "Invalid amount or nonce"}), 400

    tx = {
        "sender": data["sender"],
        "recipient": data["recipient"],
        "amount": amount,
        "public_key": data["public_key"],
        "signature": data["signature"],
        "nonce": nonce,
    }

    valid, reason = validate_normal_transaction(tx)

    if not valid:
        return jsonify({"error": reason}), 400

    with lock:
        chain_valid, chain_error, _, _, _ = replay_chain(chain)

        if not chain_valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "details": chain_error,
            }), 503

        if any(p["sender"] == tx["sender"] for p in pending_transactions):
            return jsonify({
                "error": "This wallet already has a pending transaction",
            }), 409

        expected_nonce = confirmed_nonce(tx["sender"])

        if tx["nonce"] != expected_nonce:
            return jsonify({
                "error": "Incorrect nonce",
                "expected_nonce": expected_nonce,
            }), 400

        try:
            balance = Decimal(calculate_balance(tx["sender"]))
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503

        if balance < Decimal(tx["amount"]):
            return jsonify({
                "error": "Insufficient test NXR balance",
                "balance": format(balance, "f"),
            }), 400

        try:
            persist_pending(tx)
        except Exception:
            app.logger.exception("Failed to persist pending transaction")
            return jsonify({"error": "Could not save pending transaction"}), 500

        pending_transactions.append(tx)

    return jsonify({
        "message": "Transaction accepted into pending pool",
        "transaction": tx,
        "note": "Test network only; transaction is not yet in a block.",
    }), 202


# ==================================================
# ROUTE: MINE BLOCK
# ==================================================

@app.post("/mine")
def mine_block():
    data = request.get_json(silent=True) or {}
    miner_address = data.get("miner_address", "")

    if not valid_address(miner_address):
        return jsonify({
            "error": "Valid miner_address is required",
        }), 400

    with lock:
        if not chain:
            return jsonify({"error": "Blockchain is not initialized"}), 500

        chain_valid, chain_error, _, _, mined = replay_chain(chain)

        if not chain_valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "details": chain_error,
            }), 503

        if mined + BLOCK_REWARD > MAX_SUPPLY:
            return jsonify({"error": "Maximum NXR test supply reached"}), 400

        _, _, balances, nonces, _ = replay_chain(chain)

        # Validate pending transactions again, in order.
        valid_pending = []
        rejected_senders = []

        for tx in list(pending_transactions):
            valid, reason = validate_normal_transaction(tx)

            if not valid:
                rejected_senders.append(tx.get("sender"))
                continue

            sender = tx["sender"]
            recipient = tx["recipient"]
            amount = Decimal(tx["amount"])
            expected_nonce = nonces.get(sender, 0)

            if tx["nonce"] != expected_nonce:
                rejected_senders.append(sender)
                continue

            if balances.get(sender, Decimal("0")) < amount:
                rejected_senders.append(sender)
                continue

            balances[sender] = balances.get(sender, Decimal("0")) - amount
            balances[recipient] = balances.get(recipient, Decimal("0")) + amount
            nonces[sender] = expected_nonce + 1
            valid_pending.append(tx)

        transactions = valid_pending + [{
            "type": "REWARD",
            "sender": "NETWORK",
            "recipient": miner_address,
            "amount": format(BLOCK_REWARD, "f"),
        }]

        block = {
            "index": len(chain),
            "timestamp": now(),
            "transactions": transactions,
            "previous_hash": chain[-1]["hash"],
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

                    for tx in list(pending_transactions):
                        cur.execute(
                            "DELETE FROM nexora_pending WHERE sender = %s",
                            (tx.get("sender"),),
                        )

        except Exception:
            app.logger.exception("Could not save mined block")
            return jsonify({"error": "Could not save block"}), 500

        finally:
            conn.close()

        chain.append(block)
        pending_transactions.clear()

        return jsonify({
            "message": "NEXORA block mined successfully",
            "reward": format(BLOCK_REWARD, "f") + " NXR",
            "miner_address": miner_address,
            "block": block,
            "length": len(chain),
            "rejected_pending_senders": rejected_senders,
            "test_network": True,
        }), 201


# ==================================================
# ROUTE: PENDING TRANSACTIONS
# ==================================================

@app.get("/transactions/pending")
def pending_transactions_route():
    with lock:
        return jsonify({
            "pending": pending_transactions,
            "count": len(pending_transactions),
        })


# ==================================================
# ROUTE: SUPPLY
# ==================================================

@app.get("/supply")
def supply():
    with lock:
        valid, error, _, _, mined = replay_chain(chain)

        if not valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "details": error,
            }), 503

        return jsonify({
            "symbol": "NXR",
            "test_network": True,
            "max_supply": str(MAX_SUPPLY),
            "total_mined_rewards": format(mined, "f"),
            "remaining_reward_supply": format(MAX_SUPPLY - mined, "f"),
            "block_reward": format(BLOCK_REWARD, "f"),
            "blocks": len(chain),
        })


# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("NEXORA server error")
    return jsonify({"error": "Internal server error"}), 500
