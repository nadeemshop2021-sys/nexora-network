from flask import Flask, jsonify, request
from hashlib import sha256
from datetime import datetime, timezone
from threading import Lock
import json

app = Flask(__name__)
lock = Lock()

DIFFICULTY = 3
MAX_BLOCKS_PER_REQUEST = 1000


def now():
    return datetime.now(timezone.utc).isoformat()


def block_hash(block):
    data = {
        "index": block["index"],
        "timestamp": block["timestamp"],
        "transactions": block["transactions"],
        "previous_hash": block["previous_hash"],
        "nonce": block["nonce"]
    }
    encoded = json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode()
    return sha256(encoded).hexdigest()


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


chain = [create_genesis()]


@app.get("/")
def home():
    return jsonify({
        "name": "NEXORA Network",
        "symbol": "NXR",
        "status": "online",
        "version": "1.0-demo",
        "message": "NEXORA server is running"
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "online",
        "blocks": len(chain)
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
            if block["hash"] != block_hash(block):
                return jsonify({
                    "valid": False,
                    "error": f"Invalid block hash at index {i}"
                }), 200

            if i == 0:
                if block["previous_hash"] != "0" * 64:
                    return jsonify({
                        "valid": False,
                        "error": "Invalid genesis block"
                    }), 200
            else:
                previous = chain[i - 1]

                if block["previous_hash"] != previous["hash"]:
                    return jsonify({
                        "valid": False,
                        "error": f"Broken link at block {i}"
                    }), 200

                if not block["hash"].startswith("0" * DIFFICULTY):
                    return jsonify({
                        "valid": False,
                        "error": f"Proof of work failed at block {i}"
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
            "index": previous["index"] + 1,
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
        chain.append(block)

        return jsonify({
            "message": "Block mined successfully",
            "block": block,
            "length": len(chain)
        }), 201


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=10000
    )
