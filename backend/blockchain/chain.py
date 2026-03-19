"""
blockchain/chain.py
===================
Lightweight private blockchain for tamper-proof intrusion audit logging.
Each block contains:
  - index, timestamp, data (alert info), previous_hash, hash, nonce (PoW)
"""

import hashlib
import json
import time
import os
from pathlib import Path


DIFFICULTY = 2  # Number of leading zeros required in hash (PoW difficulty)


class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def proof_of_work(self):
        self.nonce = 0
        computed = self.compute_hash()
        while not computed.startswith('0' * DIFFICULTY):
            self.nonce += 1
            computed = self.compute_hash()
        self.hash = computed
        return computed

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash,
            'nonce': self.nonce,
        }


class Blockchain:
    CHAIN_FILE = Path(__file__).parent / 'chain.json'

    def __init__(self):
        self.chain = []
        self._load_or_create()

    def _load_or_create(self):
        if self.CHAIN_FILE.exists():
            self._load_chain()
            if not self.is_valid():
                print("⚠️  Chain tampered! Reinitialising...")
                self.chain = []
                self._create_genesis()
        else:
            self._create_genesis()

    def _create_genesis(self):
        genesis = Block(
            index=0,
            timestamp=time.time(),
            data={'message': 'Genesis Block — IDS Audit Chain Initialised'},
            previous_hash='0' * 64,
        )
        genesis.proof_of_work()
        self.chain.append(genesis)
        self._save_chain()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _save_chain(self):
        os.makedirs(self.CHAIN_FILE.parent, exist_ok=True)
        with open(self.CHAIN_FILE, 'w') as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    def _load_chain(self):
        with open(self.CHAIN_FILE, 'r') as f:
            raw = json.load(f)
        self.chain = [
            Block(
                index=b['index'],
                timestamp=b['timestamp'],
                data=b['data'],
                previous_hash=b['previous_hash'],
                nonce=b['nonce'],
            )
            for b in raw
        ]
        # Restore saved hashes (don't recompute — validation checks them)
        for i, b_dict in enumerate(raw):
            self.chain[i].hash = b_dict['hash']

    # ── Core operations ───────────────────────────────────────────────────────

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, data: dict) -> Block:
        block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=self.last_block.hash,
        )
        block.proof_of_work()
        self.chain.append(block)
        self._save_chain()
        return block

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            if curr.hash != curr.compute_hash():
                return False
            if curr.previous_hash != prev.hash:
                return False
        return True

    def get_all_blocks(self):
        return [b.to_dict() for b in self.chain]

    def get_alert_blocks(self):
        """Return only alert blocks (non-genesis)."""
        return [b.to_dict() for b in self.chain[1:]]

    def verify_block(self, index: int) -> dict:
        if index >= len(self.chain):
            return {'valid': False, 'error': 'Block index out of range'}
        block = self.chain[index]
        recomputed = block.compute_hash()
        return {
            'valid': recomputed == block.hash,
            'block_index': index,
            'stored_hash': block.hash,
            'recomputed_hash': recomputed,
        }


# Singleton instance
_blockchain_instance = None

def get_blockchain() -> Blockchain:
    global _blockchain_instance
    if _blockchain_instance is None:
        _blockchain_instance = Blockchain()
    return _blockchain_instance
