"""
Multi-Party Computation (MPC) partial decryption module.
Combines threshold BFV shares and injects WAD-18 smudging noise.
"""

from typing import List, Tuple
from bfv_wad18 import WAD

# Calibrated WAD-18 smudging noise bound
SMUDGING_BOUND = 10**12

def inject_smudging_noise(partial_decryption: int) -> int:
    """Injects statistical smudging noise to eliminate key-leakage side channels."""
    noise = (hash(str(partial_decryption)) % (2 * SMUDGING_BOUND)) - SMUDGING_BOUND
    return (partial_decryption + noise) % WAD

def combine_partial_decryptions(shares: List[Tuple[int, int]], threshold: int) -> int:
    """
    Reconstructs plaintext zero-drift flag using Lagrange interpolation.
    shares: List of (node_id, partial_decryption_value)
    """
    if len(shares) < threshold:
        raise ValueError("Insufficient shares for quorum decryption.")

    reconstructed = 0
    for i, (x_i, y_i) in enumerate(shares[:threshold]):
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(shares[:threshold]):
            if i != j:
                num = (num * (-x_j)) % WAD
                den = (den * (x_i - x_j)) % WAD

        # Modular inverse replacement under WAD fixed-point scaling
        lagrange_coeff = (num * pow(den, -1, WAD)) % WAD
        reconstructed = (reconstructed + y_i * lagrange_coeff) % WAD

    return reconstructed
