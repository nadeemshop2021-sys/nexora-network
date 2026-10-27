
import os
import json
from hashlib import sha256
from datetime import datetime, timezone
from threading import Lock

import psycopg2
from psycopg2.extras import Json
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ.get("DATABASE_URL")
DIFFICULTY = 3
MAX_SUPPLY = 21_000_000
lock = Lock()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is missing")


def get_db():
    return psycopg2.connect(DATABASE_URL)


def now():
    return datetime.now(timezone.utc).isoformat()


def payload(block):
    return {
        "index": block["index"],
        "timestamp": block["timestamp"],
        "transactions": block["transactions"],
        "previous_hash": block["previous_hash"],
        "nonce": block["nonce"]
    }


def block_hash(block):
    raw = json.dumps(
        payload(block),
        sort_keys=True,
        separators=(",", ":")
    ).encode()
    return sha256(raw).hexdigest()


def create_genesis():
    block = {
        "index": 0,
        "timestamp": now(),
        "transactions": [],
        "previous_hash": "0" * 64,
        "nonce": 0
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
            block["hash"]
        )
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
                            "hash": row[5]
                        })
    finally:
        conn.close()


chain = []
init_db()


@app.get("/")
def home():
    return jsonify({
        "name": "NEXORA Network",
        "symbol": "NXR",
        "status": "online",
        "version": "3.0-prototype",
        "storage": "PostgreSQL"
    })


@app.get("/health")
def health():
    with lock:
        return jsonify({
            "status": "online",
            "blocks": len(chain),
            "storage": "PostgreSQL"
        })


@app.get("/chain")
def get_chain():
    with lock:
        return jsonify({
            "length": len(chain),
            "difficulty": DIFFICULTY,
            "chain": chain
        })


@app.get("/verify")
def verify_chain():
    with lock:
        for i, block in enumerate(chain):
            if block.get("hash") != block_hash(block):
                return jsonify({
                    "valid": False,
                    "error": f"Invalid hash at block {i}"
                }), 200

            if i == 0:
                if block["previous_hash"] != "0" * 64:
                    return jsonify({
                        "valid": False,
                        "error": "Invalid genesis"
                    }), 200
            else:
                if block["index"] != i:
                    return jsonify({
                        "valid": False,
                        "error": f"Invalid index at block {i}"
                    }), 200

                if block["previous_hash"] != chain[i - 1]["hash"]:
                    return jsonify({
                        "valid": False,
                        "error": f"Broken link at block {i}"
                    }), 200

                if not block["hash"].startswith("0" * DIFFICULTY):
                    return jsonify({
                        "valid": False,
                        "error": f"Invalid proof of work at block {i}"
                    }), 200

        return jsonify({
            "valid": True,
            "blocks": len(chain),
            "message": "NEXORA chain is valid"
        })


@app.post("/mine")
def mine_block():
    with lock:
        previous = chain[-1]

        block = {
            "index": len(chain),
            "timestamp": now(),
            "transactions": [],
            "previous_hash": previous["hash"],
            "nonce": 0
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
        finally:
            conn.close()

        chain.append(block)

        return jsonify({
            "message": "NEXORA prototype block saved",
            "block": block,
            "length": len(chain)
        }), 201


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("NEXORA server error")
    return jsonify({"error": "Internal server error"}), 500
