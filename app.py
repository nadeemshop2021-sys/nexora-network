import os
import json
import hashlib
import base64
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import psycopg2
from psycopg2.extras import RealDictCursor, Json
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


app = Flask(__name__)

# =========================================================
# NEXORA NETWORK CONFIGURATION
# =========================================================

DATABASE_URL = os.environ.get("DATABASE_URL")

DIFFICULTY = 3
BLOCK_REWARD = Decimal("100")
MAX_SUPPLY = Decimal("21000000")

ZERO_HASH = "0" * 64

ADDRESS_PATTERN = re.compile(r"^NXR[0-9A-F]{40}$")
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PUBKEY_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


# =========================================================
# DATABASE
# =========================================================

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is missing")

    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor,
        connect_timeout=15
    )


def init_db():
    conn = get_db()

    try:
        with conn:
            with conn.cursor() as cur:

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS nexora_blocks (
                        "index" BIGINT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        transactions JSONB NOT NULL,
                        previous_hash TEXT NOT NULL,
                        nonce BIGINT NOT NULL,
                        hash TEXT NOT NULL
                    )
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS nexora_pending (
                        id BIGSERIAL PRIMARY KEY,
                        sender TEXT NOT NULL UNIQUE,
                        transaction_data JSONB NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS nexora_nonces (
                        address TEXT PRIMARY KEY,
                        next_nonce BIGINT NOT NULL DEFAULT 0
                    )
                """)

    finally:
        conn.close()


# =========================================================
# GENERAL HELPERS
# =========================================================

def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def valid_address(address):
    return (
        isinstance(address, str)
        and ADDRESS_PATTERN.fullmatch(address) is not None
    )


def parse_amount(value):
    try:
        amount = Decimal(str(value))

        if not amount.is_finite():
            return None

        if amount <= 0:
            return None

        if amount.as_tuple().exponent < -8:
            return None

        if amount > MAX_SUPPLY:
            return None

        return amount

    except (InvalidOperation, ValueError, TypeError):
        return None


def amount_text(value):
    amount = Decimal(str(value))
    return format(amount.normalize(), "f")


def get_block_payload(block):
    return {
        "index": int(block["index"]),
        "timestamp": str(block["timestamp"]),
        "transactions": block["transactions"],
        "previous_hash": str(block["previous_hash"]),
        "nonce": int(block["nonce"])
    }


def calculate_block_hash(block):
    return sha256_text(canonical_json(get_block_payload(block)))


def make_genesis():
    block = {
        "index": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "transactions": [],
        "previous_hash": ZERO_HASH,
        "nonce": 0
    }

    block["hash"] = calculate_block_hash(block)

    return block


def normalize_block(row):
    transactions = row["transactions"]

    if isinstance(transactions, str):
        transactions = json.loads(transactions)

    return {
        "index": int(row["index"]),
        "timestamp": str(row["timestamp"]),
        "transactions": transactions,
        "previous_hash": str(row["previous_hash"]),
        "nonce": int(row["nonce"]),
        "hash": str(row["hash"])
    }


# =========================================================
# BLOCKCHAIN DATABASE OPERATIONS
# =========================================================

def load_chain():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT "index", timestamp, transactions,
                       previous_hash, nonce, hash
                FROM nexora_blocks
                ORDER BY "index" ASC
            """)

            rows = cur.fetchall()

        chain = [normalize_block(row) for row in rows]

    finally:
        conn.close()

    if not chain:
        genesis = make_genesis()

        conn = get_db()

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO nexora_blocks
                        ("index", timestamp, transactions,
                         previous_hash, nonce, hash)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT ("index") DO NOTHING
                    """, (
                        genesis["index"],
                        genesis["timestamp"],
                        Json(genesis["transactions"]),
                        genesis["previous_hash"],
                        genesis["nonce"],
                        genesis["hash"]
                    ))

        finally:
            conn.close()

        return load_chain()

    return chain


def save_block(block):
    conn = get_db()

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO nexora_blocks
                    ("index", timestamp, transactions,
                     previous_hash, nonce, hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    block["index"],
                    block["timestamp"],
                    Json(block["transactions"]),
                    block["previous_hash"],
                    block["nonce"],
                    block["hash"]
                ))

    finally:
        conn.close()


def get_pending_transactions():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT transaction_data
                FROM nexora_pending
                ORDER BY id ASC
            """)

            rows = cur.fetchall()

        result = []

        for row in rows:
            tx = row["transaction_data"]

            if isinstance(tx, str):
                tx = json.loads(tx)

            result.append(tx)

        return result

    finally:
        conn.close()


# =========================================================
# TRANSACTION SIGNATURES
# =========================================================

def transaction_message(tx):
    message = {
        "sender": tx["sender"],
        "recipient": tx["recipient"],
        "amount": amount_text(tx["amount"]),
        "nonce": int(tx["nonce"])
    }

    return canonical_json(message).encode("utf-8")


def address_from_public_key(public_key_hex):
    public_key_bytes = bytes.fromhex(public_key_hex)

    digest = hashlib.sha256(public_key_bytes).digest()

    return "NXR" + digest[:20].hex().upper()


def validate_signature(tx):
    try:
        sender = tx.get("sender")
        recipient = tx.get("recipient")
        public_key_hex = tx.get("public_key")
        signature_text = tx.get("signature")

        if not valid_address(sender):
            return False

        if not valid_address(recipient):
            return False

        if not isinstance(public_key_hex, str):
            return False

        if not PUBKEY_PATTERN.fullmatch(public_key_hex):
            return False

        if address_from_public_key(public_key_hex) != sender:
            return False

        public_key_bytes = bytes.fromhex(public_key_hex)

        signature = base64.b64decode(
            signature_text,
            validate=True
        )

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        public_key.verify(
            signature,
            transaction_message(tx)
        )

        return True

    except Exception:
        return False


# =========================================================
# BLOCKCHAIN VALIDATION
# =========================================================

def replay_chain(chain):
    """
    Rebuild balances and nonces from the blockchain.

    Historical compatibility:
    Blocks without rewards are accepted because the existing
    NEXORA chain contains older rewardless blocks.

    New blocks created by this application receive one reward.
    """

    if not chain:
        return False, "Blockchain is empty", {}, {}, Decimal("0")

    balances = {}
    nonces = {}
    total_rewards = Decimal("0")

    # -----------------------------------------------------
    # GENESIS
    # -----------------------------------------------------

    genesis = chain[0]

    if genesis["index"] != 0:
        return False, "Genesis index must be zero", {}, {}, Decimal("0")

    if genesis["previous_hash"] != ZERO_HASH:
        return False, "Invalid genesis previous_hash", {}, {}, Decimal("0")

    if genesis["transactions"] != []:
        return False, "Genesis transactions must be empty", {}, {}, Decimal("0")

    if genesis["hash"] != calculate_block_hash(genesis):
        return False, "Genesis hash mismatch", {}, {}, Decimal("0")

    # -----------------------------------------------------
    # BLOCKS
    # -----------------------------------------------------

    for position, block in enumerate(chain[1:], start=1):

        if block["index"] != position:
            return (
                False,
                f"Invalid block index at position {position}",
                balances,
                nonces,
                total_rewards
            )

        previous = chain[position - 1]

        if block["previous_hash"] != previous["hash"]:
            return (
                False,
                f"Previous hash mismatch at block {position}",
                balances,
                nonces,
                total_rewards
            )

        if block["hash"] != calculate_block_hash(block):
            return (
                False,
                f"Block {position} hash mismatch",
                balances,
                nonces,
                total_rewards
            )

        if not block["hash"].startswith("0" * DIFFICULTY):
            return (
                False,
                f"Proof of work invalid at block {position}",
                balances,
                nonces,
                total_rewards
            )

        transactions = block.get("transactions")

        if not isinstance(transactions, list):
            return (
                False,
                f"Block {position} transactions must be a list",
                balances,
                nonces,
                total_rewards
            )

        reward_count = 0

        # Process transactions in their original order.
        for tx in transactions:

            if not isinstance(tx, dict):
                return (
                    False,
                    f"Invalid transaction in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            # -------------------------------------------------
            # MINING REWARD
            # -------------------------------------------------

            if tx.get("type") == "REWARD":

                reward_count += 1

                if reward_count > 1:
                    return (
                        False,
                        f"Block {position} has multiple rewards",
                        balances,
                        nonces,
                        total_rewards
                    )

                if tx.get("sender") != "NETWORK":
                    return (
                        False,
                        f"Invalid reward sender in block {position}",
                        balances,
                        nonces,
                        total_rewards
                    )

                recipient = tx.get("recipient")

                if not valid_address(recipient):
                    return (
                        False,
                        f"Invalid reward recipient in block {position}",
                        balances,
                        nonces,
                        total_rewards
                    )

                try:
                    reward = Decimal(str(tx.get("amount")))
                except Exception:
                    return (
                        False,
                        f"Invalid reward amount in block {position}",
                        balances,
                        nonces,
                        total_rewards
                    )

                if reward != BLOCK_REWARD:
                    return (
                        False,
                        f"Incorrect reward amount in block {position}",
                        balances,
                        nonces,
                        total_rewards
                    )

                total_rewards += reward

                if total_rewards > MAX_SUPPLY:
                    return (
                        False,
                        "Maximum coin supply exceeded",
                        balances,
                        nonces,
                        total_rewards
                    )

                balances[recipient] = (
                    balances.get(recipient, Decimal("0")) + reward
                )

                continue

            # -------------------------------------------------
            # NORMAL TRANSACTION
            # -------------------------------------------------

            required = {
                "sender",
                "recipient",
                "amount",
                "nonce",
                "public_key",
                "signature"
            }

            if not required.issubset(tx.keys()):
                return (
                    False,
                    f"Missing transaction fields in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            sender = tx["sender"]
            recipient = tx["recipient"]

            if not valid_address(sender) or not valid_address(recipient):
                return (
                    False,
                    f"Invalid address in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            amount = parse_amount(tx["amount"])

            if amount is None:
                return (
                    False,
                    f"Invalid amount in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            try:
                tx_nonce = int(tx["nonce"])
            except Exception:
                return (
                    False,
                    f"Invalid nonce in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            expected_nonce = nonces.get(sender, 0)

            if tx_nonce != expected_nonce:
                return (
                    False,
                    f"Incorrect nonce in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            if not validate_signature(tx):
                return (
                    False,
                    f"Invalid signature in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            sender_balance = balances.get(sender, Decimal("0"))

            if sender_balance < amount:
                return (
                    False,
                    f"Insufficient balance in block {position}",
                    balances,
                    nonces,
                    total_rewards
                )

            balances[sender] = sender_balance - amount

            balances[recipient] = (
                balances.get(recipient, Decimal("0")) + amount
            )

            nonces[sender] = expected_nonce + 1

    return True, "Blockchain is valid", balances, nonces, total_rewards


def checked_chain():
    chain = load_chain()

    valid, message, balances, nonces, rewards = replay_chain(chain)

    return chain, valid, message, balances, nonces, rewards


# =========================================================
# PENDING TRANSACTION VALIDATION
# =========================================================

def validate_pending_pool(chain, balances, nonces, pending):
    """
    Validate pending transactions without modifying confirmed
    blockchain balances or nonces.
    """

    pending_senders = set()
    pending_spent = {}

    for tx in pending:

        if not isinstance(tx, dict):
            return False, "Invalid pending transaction"

        sender = tx.get("sender")

        if sender in pending_senders:
            return False, "Multiple pending transactions from one wallet"

        if sender == "NETWORK":
            return False, "Network rewards cannot be pending transactions"

        if not validate_signature(tx):
            return False, "Invalid pending transaction signature"

        amount = parse_amount(tx.get("amount"))

        if amount is None:
            return False, "Invalid pending transaction amount"

        expected_nonce = nonces.get(sender, 0)

        if int(tx.get("nonce", -1)) != expected_nonce:
            return False, "Pending transaction nonce is incorrect"

        pending_senders.add(sender)

        pending_spent[sender] = (
            pending_spent.get(sender, Decimal("0")) + amount
        )

        if balances.get(sender, Decimal("0")) < pending_spent[sender]:
            return False, "Pending transaction exceeds wallet balance"

    return True, "Pending transactions are valid"


# =========================================================
# API: HOME AND HEALTH
# =========================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "name": "NEXORA Network",
        "symbol": "NXR",
        "status": "online",
        "test_network": True,
        "api": "/health"
    })


@app.route("/health", methods=["GET"])
def health():
    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        status = "ok" if valid else "error"

        return jsonify({
            "status": status,
            "storage": "PostgreSQL",
            "test_network": True,
            "blocks": len(chain),
            "chain_valid": valid,
            "message": message,
            "total_mined": amount_text(rewards),
            "max_supply": amount_text(MAX_SUPPLY)
        }), 200 if valid else 500

    except Exception as exc:
        app.logger.exception("Health check failed")

        return jsonify({
            "status": "error",
            "storage": "PostgreSQL",
            "test_network": True,
            "error": str(exc)
        }), 500


# =========================================================
# API: BLOCKCHAIN
# =========================================================

@app.route("/chain", methods=["GET"])
def get_blockchain():
    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        return jsonify({
            "chain": chain,
            "length": len(chain),
            "chain_valid": valid,
            "message": message,
            "block_reward": amount_text(BLOCK_REWARD),
            "max_supply": amount_text(MAX_SUPPLY),
            "total_mined": amount_text(rewards),
            "test_network": True
        })

    except Exception as exc:
        app.logger.exception("Chain endpoint failed")

        return jsonify({
            "error": str(exc)
        }), 500


@app.route("/verify", methods=["GET"])
def verify_chain():
    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        return jsonify({
            "valid": valid,
            "message": message,
            "blocks": len(chain),
            "total_mined": amount_text(rewards)
        }), 200 if valid else 400

    except Exception as exc:
        app.logger.exception("Verify endpoint failed")

        return jsonify({
            "valid": False,
            "error": str(exc)
        }), 500


# =========================================================
# API: WALLET
# =========================================================

@app.route("/wallet/create", methods=["POST"])
def wallet_create():
    import secrets

    # Wallet keys are generated locally for this response.
    # The server does not store private keys.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey
    )
    from cryptography.hazmat.primitives import serialization

    private_key = Ed25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    public_hex = public_bytes.hex()
    address = address_from_public_key(public_hex)

    return jsonify({
        "address": address,
        "public_key": public_hex,
        "private_key": private_bytes.hex(),
        "warning": "Keep your private key secret. Never share it.",
        "test_network": True
    }), 201


@app.route("/wallet/<address>/balance", methods=["GET"])
def wallet_balance(address):
    if not valid_address(address):
        return jsonify({"error": "Invalid NXR address"}), 400

    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        if not valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "message": message
            }), 500

        confirmed = balances.get(address, Decimal("0"))

        pending = get_pending_transactions()

        pending_spent = sum(
            (
                parse_amount(tx.get("amount")) or Decimal("0")
                for tx in pending
                if tx.get("sender") == address
            ),
            Decimal("0")
        )

        return jsonify({
            "address": address,
            "balance": amount_text(confirmed),
            "pending_spent": amount_text(pending_spent),
            "available_balance": amount_text(
                max(Decimal("0"), confirmed - pending_spent)
            ),
            "symbol": "NXR"
        })

    except Exception as exc:
        app.logger.exception("Balance endpoint failed")

        return jsonify({"error": str(exc)}), 500


@app.route("/wallet/<address>/nonce", methods=["GET"])
def wallet_nonce(address):
    if not valid_address(address):
        return jsonify({"error": "Invalid NXR address"}), 400

    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        if not valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "message": message
            }), 500

        # Nonce is derived from confirmed blockchain history.
        return jsonify({
            "address": address,
            "nonce": nonces.get(address, 0)
        })

    except Exception as exc:
        app.logger.exception("Nonce endpoint failed")

        return jsonify({"error": str(exc)}), 500


# =========================================================
# API: SUBMIT TRANSACTION
# =========================================================

@app.route("/transaction", methods=["POST"])
def submit_transaction():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON request body required"}), 400

    required = {
        "sender",
        "recipient",
        "amount",
        "nonce",
        "public_key",
        "signature"
    }

    if not required.issubset(data.keys()):
        return jsonify({
            "error": "Missing required transaction fields",
            "required": sorted(required)
        }), 400

    tx = {
        "sender": data["sender"],
        "recipient": data["recipient"],
        "amount": data["amount"],
        "nonce": data["nonce"],
        "public_key": data["public_key"],
        "signature": data["signature"]
    }

    if not valid_address(tx["sender"]):
        return jsonify({"error": "Invalid sender address"}), 400

    if not valid_address(tx["recipient"]):
        return jsonify({"error": "Invalid recipient address"}), 400

    if tx["sender"] == tx["recipient"]:
        return jsonify({"error": "Sender and recipient must differ"}), 400

    amount = parse_amount(tx["amount"])

    if amount is None:
        return jsonify({"error": "Invalid transaction amount"}), 400

    try:
        tx["nonce"] = int(tx["nonce"])
    except Exception:
        return jsonify({"error": "Invalid nonce"}), 400

    if tx["nonce"] < 0:
        return jsonify({"error": "Nonce cannot be negative"}), 400

    tx["amount"] = amount_text(amount)

    if not validate_signature(tx):
        return jsonify({
            "error": "Invalid wallet signature or public key"
        }), 400

    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        if not valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "message": message
            }), 500

        sender = tx["sender"]

        expected_nonce = nonces.get(sender, 0)

        if tx["nonce"] != expected_nonce:
            return jsonify({
                "error": "Incorrect nonce",
                "expected_nonce": expected_nonce,
                "received_nonce": tx["nonce"]
            }), 400

        pending = get_pending_transactions()

        for existing in pending:
            if existing.get("sender") == sender:
                return jsonify({
                    "error": "This wallet already has a pending transaction",
                    "message": "Wait until the existing transaction is mined."
                }), 409

        pending_spent = sum(
            (
                parse_amount(existing.get("amount")) or Decimal("0")
                for existing in pending
                if existing.get("sender") == sender
            ),
            Decimal("0")
        )

        available = (
            balances.get(sender, Decimal("0")) - pending_spent
        )

        if available < amount:
            return jsonify({
                "error": "Insufficient balance",
                "balance": amount_text(
                    balances.get(sender, Decimal("0"))
                ),
                "available_balance": amount_text(
                    max(Decimal("0"), available)
                )
            }), 400

        conn = get_db()

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO nexora_pending
                        (sender, transaction_data)
                        VALUES (%s, %s)
                    """, (
                        sender,
                        Json(tx)
                    ))

        except psycopg2.errors.UniqueViolation:
            return jsonify({
                "error": "This wallet already has a pending transaction"
            }), 409

        finally:
            conn.close()

        return jsonify({
            "message": "Transaction accepted",
            "transaction": tx,
            "status": "pending"
        }), 201

    except Exception as exc:
        app.logger.exception("Transaction submission failed")

        return jsonify({"error": str(exc)}), 500


# =========================================================
# API: PENDING TRANSACTIONS
# =========================================================

@app.route("/transactions/pending", methods=["GET"])
def pending_transactions():
    try:
        pending = get_pending_transactions()

        return jsonify({
            "pending": pending,
            "count": len(pending)
        })

    except Exception as exc:
        app.logger.exception("Pending endpoint failed")

        return jsonify({"error": str(exc)}), 500


# =========================================================
# API: MINE BLOCK
# =========================================================

@app.route("/mine", methods=["POST"])
def mine_block():
    data = request.get_json(silent=True) or {}

    miner = data.get("miner") or data.get("address")

    if not valid_address(miner):
        return jsonify({
            "error": "Provide a valid miner address",
            "example": {
                "miner": "NXR followed by 40 uppercase hexadecimal characters"
            }
        }), 400

    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        if not valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "message": message
            }), 500

        pending = get_pending_transactions()

        # Check pending transactions before mining.
        pending_ok, pending_message = validate_pending_pool(
            chain, balances, nonces, pending
        )

        if not pending_ok:
            return jsonify({
                "error": "Pending pool validation failed",
                "message": pending_message
            }), 400

        # Check supply before issuing a new reward.
        if rewards + BLOCK_REWARD > MAX_SUPPLY:
            return jsonify({
                "error": "Maximum NXR supply reached"
            }), 400

        transactions = list(pending)

        # Reward is appended after normal transactions.
        transactions.append({
            "type": "REWARD",
            "sender": "NETWORK",
            "recipient": miner,
            "amount": amount_text(BLOCK_REWARD)
        })

        previous_block = chain[-1]

        block = {
            "index": len(chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "transactions": transactions,
            "previous_hash": previous_block["hash"],
            "nonce": 0
        }

        # Proof of work
        while True:
            block["hash"] = calculate_block_hash(block)

            if block["hash"].startswith("0" * DIFFICULTY):
                break

            block["nonce"] += 1

        # Save block and clear the pending pool atomically.
        conn = get_db()

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO nexora_blocks
                        ("index", timestamp, transactions,
                         previous_hash, nonce, hash)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        block["index"],
                        block["timestamp"],
                        Json(block["transactions"]),
                        block["previous_hash"],
                        block["nonce"],
                        block["hash"]
                    ))

                    cur.execute("DELETE FROM nexora_pending")

        finally:
            conn.close()

        return jsonify({
            "message": "Block mined successfully",
            "block": block,
            "reward": amount_text(BLOCK_REWARD),
            "miner": miner,
            "transactions_included": len(pending),
            "test_network": True
        }), 201

    except Exception as exc:
        app.logger.exception("Mining failed")

        return jsonify({"error": str(exc)}), 500


# =========================================================
# API: TOTAL SUPPLY
# =========================================================

@app.route("/supply", methods=["GET"])
def supply():
    try:
        chain, valid, message, balances, nonces, rewards = checked_chain()

        if not valid:
            return jsonify({
                "error": "Blockchain validation failed",
                "message": message
            }), 500

        return jsonify({
            "symbol": "NXR",
            "total_mined": amount_text(rewards),
            "max_supply": amount_text(MAX_SUPPLY),
            "remaining": amount_text(MAX_SUPPLY - rewards),
            "block_reward": amount_text(BLOCK_REWARD),
            "difficulty": DIFFICULTY,
            "test_network": True
        })

    except Exception as exc:
        app.logger.exception("Supply endpoint failed")

        return jsonify({"error": str(exc)}), 500


# =========================================================
# STARTUP
# =========================================================

with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
