"""
Sovereign Node Execution Daemon.
Synchronizes local R^3 state loops with on-chain CSL commits.
"""

import hashlib
import json
import time
from typing import Dict, Any

class SovereignNodeDaemon:
    def __init__(self, node_id: int, ledger_path: str):
        self.node_id = node_id
        self.ledger_path = ledger_path
        self.current_state_hash = "0x" + "0" * 64

    def compute_wad18_state_hash(self, payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash of WAD-18 normalized state."""
        canonical_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        return hashlib.sha256(canonical_bytes).hexdigest()

    def step_refinement_loop(self, input_vector: Dict[str, int]) -> str:
        """Executes recursive step and appends hash commitment to local storage."""
        state_payload = {
            "node_id": self.node_id,
            "timestamp": int(time.time()),
            "inputs": input_vector,
            "prev_hash": self.current_state_hash
        }
        
        self.current_state_hash = self.compute_wad18_state_hash(state_payload)

        with open(self.ledger_path, "a") as f:
            f.write(json.dumps({"hash": self.current_state_hash, "payload": state_payload}) + "\n")

        return self.current_state_hash
