import unittest
from src.mpc_decrypt import inject_smudging_noise, combine_partial_decryptions

class TestMPCThreshold(unittest.TestCase):
    def test_smudging_noise_bounds(self):
        base_val = 500000000000000000
        smudged = inject_smudging_noise(base_val)
        self.assertNotEqual(base_val, smudged)

    def test_insufficient_shares_rejection(self):
        shares = [(1, 100), (2, 200)]
        with self.assertRaises(ValueError):
            combine_partial_decryptions(shares, threshold=3)

if __name__ == "__main__":
    unittest.main()
