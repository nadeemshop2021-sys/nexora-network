from flask import Flask, jsonify, request
from flask_cors import CORS
from hashlib import sha256
from datetime import datetime, timezone
from threading import Lock
import json

app = Flask(__name__)
CORS(app)

lock = Lock()
DIFFICULTY = 3
MAX_SUPPLY = 21_000_000

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
        payload(block), sort_keys=True, separators=(",", ":")
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

chain = [create_genesis()]

@app.get("/")
def home():
    return jsonify({
        "name": "NEXORA Network",
        "symbol": "NXR",
        "status": "online",
        "version": "2.0-demo"
    })

@app.get("/health")
def health():
    return jsonify({"status": "online", "blocks": len(chain)})

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
                })

            if i == 0:
                if block["previous_hash"] != "0" * 64:
                    return jsonify({"valid": False, "error": "Invalid genesis"})
            else:
                if block["previous_hash"] != chain[i - 1]["hash"]:
                    return jsonify({
                        "valid": False,
                        "error": f"Broken link at block {i}"
                    })

                if not block["hash"].startswith("0" * DIFFICULTY):
                    return jsonify({
                        "valid": False,
                        "error": f"Invalid proof of work at block {i}"
                    })

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
        chain.append(block)

        return jsonify({
            "message": "Demo block mined",
            "block": block,
            "length": len(chain)
        }), 201

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404
