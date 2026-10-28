import os
import json
import base64
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from datetime import datetime, timezone
from threading import RLock

import psycopg2
from psycopg2.extras import Json
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
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

lock = RLock()
chain = []
pending_transactions = []

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is missing")


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

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


# --------------------------------------------------
# WALLET
# --------------------------------------------------

def wallet_address(public_key_hex):
    return (
        "NXR"
        + sha256(bytes.fromhex(public_key_hex))
        .hexdigest()[:40]
        .upper()
    )


def valid_address(address):
    if not isinstance(address, str):
        return False

    if len(address) != 43 or not address.startswith("NXR"):
        return False

    return all(
        c in "0123456789ABCDEF"
        for c in address[3:]
    )


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
            "Save your private key securely. "
            "Never share it or upload it to GitHub."
        ),
    }


# --------------------------------------------------
# TRANSACTION SIGNATURE
# --------------------------------------------------

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

        if len(public_bytes) != 32:
            return False

        if wallet_address(public_hex) != tx["sender"]:
            return False

        public_key = Ed25519PublicKey.from_public_bytes(
            public_bytes
        )

        signature = base64.b64decode(
            tx["signature"],
            validate=True,
        )

        public_key.verify(
            signature,
            transaction_message(tx),
        )

        return True

    except Exception:
        return False


# --------------------------------------------------
# BLOCKCHAIN
# --------------------------------------------------

def block_payload(block):
    return {
        "index": block["index"],
        "timestamp": block["timestamp"],
        "transactions": block["transactions"],
        "previous_hash": block["previous_hash"],
        "nonce": block["nonce"],
    }


def block_hash(block):
    return sha256(
        canonical_json(block_payload(block))
    ).hexdigest()


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
        (
            block_index,
            block_timestamp,
            transactions,
            previous_hash,
            nonce,
            block_hash
        )
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
                    SELECT
                        block_index,
                        block_timestamp,
                        transactions,
                        previous_hash,
                        nonce,
                        block_hash
                    FROM nexora_blocks
                    ORDER BY block_index ASC
                """)

                rows = cur.fetchall()

                if not rows:
                    genesis = create_genesis()
                    save_block(cur, genesis)
                    chain = [genesis]

                else:
                    loaded_chain = []

                    for row in rows:
                        transactions = row[2]

                        if isinstance(transactions, str):
                            transactions = json.loads(
                                transactions
                            )

                        loaded_chain.append({
                            "index": row[0],
                            "timestamp": row[1],
                            "transactions": transactions,
                            "previous_hash": row[3],
                            "nonce": row[4],
                            "hash": row[5],
                        })

                    chain = loaded_chain

    finally:
        conn.close()


# --------------------------------------------------
# TRANSACTIONS AND BALANCE
# --------------------------------------------------

def all_transactions():
    return [
        tx
        for block in chain
        for tx in block["transactions"]
    ]


def as_amount(value):
    if isinstance(value, bool):
        raise ValueError("Invalid amount")

    amount = Decimal(str(value))

    if (
        not amount.is_finite()
        or amount <= 0
        or amount > Decimal("1000000000")
    ):
        raise ValueError("Invalid amount")

    if amount != amount.quantize(
        Decimal("0.00000001")
    ):
        raise ValueError(
            "Maximum 8 decimal places allowed"
        )

    return format(amount, "f")


def calculate_balance(address):
    balance = Decimal("0")

    for tx in all_transactions():
        amount = Decimal(str(tx["amount"]))

        # Mining reward
        if tx.get("type") == "REWARD":
            if tx.get("recipient") == address:
                balance += amount

            continue

        # Normal transaction
        if tx.get("recipient") == address:
            balance += amount

        if tx.get("sender") == address:
            balance -= amount

    return format(balance, "f")


def total_rewards():
    total = Decimal("0")

    for tx in all_transactions():
        if tx.get("type") == "REWARD":
            total += Decimal(str(tx["amount"]))

    return total


def next_nonce(address):
    conn = get_db()

    try:
        with conn:
            with conn.cursor() as cur:

                cur.execute("""
                    INSERT INTO nexora_nonces
                    (wallet_address, next_nonce)
                    VALUES (%s, 0)
                    ON CONFLICT (wallet_address)
                    DO NOTHING
                """, (address,))

                cur.execute("""
                    SELECT next_nonce
                    FROM nexora_nonces
                    WHERE wallet_address = %s
                """, (address,))

                return cur.fetchone()[0]

    finally:
        conn.close()


# Load existing blockchain
init_db()


# --------------------------------------------------
# HOME AND HEALTH
# --------------------------------------------------

@app.get("/")
def home():
    return jsonify({
        "name": "NEXORA Network",
        "symbol": "NXR",
        "status": "online",
        "version": "5.0-reward-testnet",
        "storage": "PostgreSQL",
        "test_network": True,
        "block_reward": "100 NXR",
        "max_supply": str(MAX_SUPPLY),
    })


@app.get("/health")
def health():
    with lock:
        return jsonify({
            "status": "online",
            "blocks": len(chain),
            "storage": "PostgreSQL",
            "test_network": True,
        })


# --------------------------------------------------
# CHAIN
# --------------------------------------------------

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
        for i, block in enumerate(chain):

            # Verify hash
            if block.get("hash") != block_hash(block):
                return jsonify({
                    "valid": False,
                    "error": f"Invalid hash at block {i}",
                })

            # Genesis
            if i == 0:
                if (
                    block["index"] != 0
                    or block["previous_hash"] != "0" * 64
                ):
                    return jsonify({
                        "valid": False,
                        "error": "Invalid genesis block",
                    })

                if block["transactions"]:
                    return jsonify({
                        "valid": False,
                        "error": "Genesis transactions are not allowed",
                    })

                continue

            # Index
            if block["index"] != i:
                return jsonify({
                    "valid": False,
                    "error": f"Invalid index at block {i}",
                })

            # Previous block link
            if block["previous_hash"] != chain[i - 1]["hash"]:
                return jsonify({
                    "valid": False,
                    "error": f"Broken link at block {i}",
                })

            # Proof of Work
            if not block["hash"].startswith(
                "0" * DIFFICULTY
            ):
                return jsonify({
                    "valid": False,
                    "error": f"Invalid proof of work at block {i}",
                })

            # Reward rules for newly created blocks.
            rewards = [
                tx for tx in block["transactions"]
                if tx.get("type") == "REWARD"
            ]

            if len(rewards) > 1:
                return jsonify({
                    "valid": False,
                    "error": f"Multiple rewards at block {i}",
                })

            for reward in rewards:
                try:
                    amount = Decimal(str(reward["amount"]))

                    if (
                        amount != BLOCK_REWARD
                        or not valid_address(
                            reward.get("recipient")
                        )
                        or reward.get("sender") != "NETWORK"
                    ):
                        return jsonify({
                            "valid": False,
                            "error": f"Invalid reward at block {i}",
                        })

                except Exception:
                    return jsonify({
                        "valid": False,
                        "error": f"Invalid reward at block {i}",
                    })

        if total_rewards() > MAX_SUPPLY:
            return jsonify({
                "valid": False,
                "error": "Maximum reward supply exceeded",
            })

        return jsonify({
            "valid": True,
            "blocks": len(chain),
            "message": "NEXORA chain is valid",
        })


# --------------------------------------------------
# CREATE WALLET
# --------------------------------------------------

@app.post("/wallet/create")
def wallet_create():
    return jsonify(create_wallet()), 201


# --------------------------------------------------
# WALLET BALANCE
# --------------------------------------------------

@app.get("/wallet/<address>/balance")
def wallet_balance(address):
    if not valid_address(address):
        return jsonify({
            "error": "Invalid wallet address",
        }), 400

    with lock:
        return jsonify({
            "address": address,
            "balance": calculate_balance(address),
            "unit": "test NXR",
            "test_network": True,
        })


# --------------------------------------------------
# WALLET NONCE
# --------------------------------------------------

@app.get("/wallet/<address>/nonce")
def wallet_nonce(address):
    if not valid_address(address):
        return jsonify({
            "error": "Invalid wallet address",
        }), 400

    return jsonify({
        "address": address,
        "nonce": next_nonce(address),
    })


# --------------------------------------------------
# CREATE TRANSACTION
# --------------------------------------------------

@app.post("/transaction")
def create_transaction():
    data = request.get_json(silent=True) or {}

    required = [
        "sender",
        "recipient",
        "amount",
        "public_key",
        "signature",
        "nonce",
    ]

    if any(key not in data for key in required):
        return jsonify({
            "error": (
                "Required fields: "
                + ", ".join(required)
            ),
        }), 400

    try:
        amount = as_amount(data["amount"])

        if isinstance(data["nonce"], bool):
            raise ValueError("Invalid nonce")

        nonce = int(data["nonce"])

        if str(nonce) != str(data["nonce"]) or nonce < 0:
            raise ValueError("Invalid nonce")

    except (
        TypeError,
        ValueError,
        InvalidOperation,
        OverflowError,
    ):
        return jsonify({
            "error": "Invalid amount or nonce",
        }), 400

    tx = {
        "sender": str(data["sender"]),
        "recipient": str(data["recipient"]),
        "amount": amount,
        "public_key": str(data["public_key"]),
        "signature": str(data["signature"]),
        "nonce": nonce,
    }

    if not valid_address(tx["sender"]):
        return jsonify({
            "error": "Invalid sender address",
        }), 400

    if not valid_address(tx["recipient"]):
        return jsonify({
            "error": "Invalid recipient address",
        }), 400

    if not verify_signature(tx):
        return jsonify({
            "error": "Invalid wallet address or signature",
        }), 400

    with lock:

        if any(
            p["sender"] == tx["sender"]
            for p in pending_transactions
        ):
            return jsonify({
                "error": (
                    "This wallet already has "
                    "a pending transaction"
                ),
            }), 409

        expected_nonce = next_nonce(tx["sender"])

        if tx["nonce"] != expected_nonce:
            return jsonify({
                "error": "Incorrect nonce",
                "expected_nonce": expected_nonce,
            }), 400

        balance = Decimal(
            calculate_balance(tx["sender"])
        )

        pending_spending = sum(
            (
                Decimal(p["amount"])
                for p in pending_transactions
                if p["sender"] == tx["sender"]
            ),
            Decimal("0"),
        )

        if balance - pending_spending < Decimal(tx["amount"]):
            return jsonify({
                "error": "Insufficient test NXR balance",
                "balance": format(balance, "f"),
            }), 400

        conn = get_db()

        try:
            with conn:
                with conn.cursor() as cur:

                    cur.execute("""
                        UPDATE nexora_nonces
                        SET next_nonce = next_nonce + 1
                        WHERE wallet_address = %s
                          AND next_nonce = %s
                    """, (
                        tx["sender"],
                        tx["nonce"],
                    ))

                    if cur.rowcount != 1:
                        return jsonify({
                            "error": "Nonce conflict; retry",
                        }), 409

            pending_transactions.append(tx)

        except Exception:
            app.logger.exception(
                "Failed to save transaction nonce"
            )

            return jsonify({
                "error": "Could not save transaction nonce",
            }), 500

        finally:
            conn.close()

    return jsonify({
        "message": "Transaction accepted into pending pool",
        "transaction": tx,
        "note": (
            "Test network only; transaction "
            "is not yet in a block."
        ),
    }), 202


# --------------------------------------------------
# MINE BLOCK AND GIVE 100 NXR REWARD
# --------------------------------------------------

@app.post("/mine")
def mine_block():
    data = request.get_json(silent=True) or {}

    miner_address = str(
        data.get("miner_address", "")
    ).strip()

    if not valid_address(miner_address):
        return jsonify({
            "error": (
                "Valid miner_address is required "
                "in the JSON request"
            ),
            "example": {
                "miner_address": "YOUR_VALID_NXR_ADDRESS"
            },
        }), 400

    with lock:

        if not chain:
            return jsonify({
                "error": "Blockchain is not initialized",
            }), 500

        # Check maximum test reward supply
        mined = total_rewards()

        if mined + BLOCK_REWARD > MAX_SUPPLY:
            return jsonify({
                "error": "Maximum NXR test supply reached",
            }), 400

        previous = chain[-1]

        # Copy pending transactions
        transactions = list(pending_transactions)

        # Add block reward
        transactions.append({
            "type": "REWARD",
            "sender": "NETWORK",
            "recipient": miner_address,
            "amount": format(BLOCK_REWARD, "f"),
        })

        block = {
            "index": len(chain),
            "timestamp": now(),
            "transactions": transactions,
            "previous_hash": previous["hash"],
            "nonce": 0,
        }

        target = "0" * DIFFICULTY

        # Server-side Proof of Work
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
            app.logger.exception(
                "Could not save mined block"
            )

            return jsonify({
                "error": "Could not save block",
            }), 500

        finally:
            conn.close()

        chain.append(block)
        pending_transactions.clear()

        return jsonify({
            "message": "NEXORA block mined successfully",
            "reward": "100 NXR",
            "miner_address": miner_address,
            "block": block,
            "length": len(chain),
            "test_network": True,
        }), 201


# --------------------------------------------------
# PENDING TRANSACTIONS
# --------------------------------------------------

@app.get("/transactions/pending")
def pending_transactions_route():
    with lock:
        return jsonify({
            "pending": pending_transactions,
            "count": len(pending_transactions),
        })


# --------------------------------------------------
# TOTAL REWARD INFORMATION
# --------------------------------------------------

@app.get("/supply")
def supply():
    with lock:
        mined = total_rewards()

        return jsonify({
            "symbol": "NXR",
            "test_network": True,
            "max_supply": str(MAX_SUPPLY),
            "total_mined_rewards": format(mined, "f"),
            "remaining_reward_supply": format(
                MAX_SUPPLY - mined,
                "f",
            ),
            "block_reward": format(
                BLOCK_REWARD,
                "f",
            ),
            "blocks": len(chain),
        })


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
    }), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("NEXORA server error")

    return jsonify({
        "error": "Internal server error",
    }), 500
