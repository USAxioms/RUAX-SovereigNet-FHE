"""
Distributed Key Generation (DKG) module for WAD-18 BFV FHE.
Generates secret polynomial shares across N nodes without revealing the master key.
"""

import os
import secrets
from typing import List, Tuple

WAD = 10**18

class DKGNode:
    def __init__(self, node_id: int, threshold: int, total_nodes: int):
        self.node_id = node_id
        self.threshold = threshold
        self.total_nodes = total_nodes
        self.coefficients = [secrets.randbelow(WAD) for _ in range(threshold)]
        self.received_shares: List[Tuple[int, int]] = []

    def evaluate_polynomial(self, x: int) -> int:
        """Evaluates local secret polynomial at point x using Horner's method."""
        result = 0
        for coeff in reversed(self.coefficients):
            result = (result * x + coeff) % WAD
        return result

    def generate_shares(self) -> List[Tuple[int, int]]:
        """Generates share tuple (node_id, evaluation) for all participants."""
        return [(i, self.evaluate_polynomial(i)) for i in range(1, self.total_nodes + 1)]

    def receive_share(self, sender_id: int, share_value: int) -> None:
        self.received_shares.append((sender_id, share_value))

    def compute_final_secret_share(self) -> int:
        """Sums received shares to obtain the final node secret share."""
        return sum(val for _, val in self.received_shares) % WAD
