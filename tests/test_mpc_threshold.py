import unittest
from unittest import mock

from src import mpc_decrypt as M
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


B = 10 ** 12
WAD = 10 ** 18


def with_hash(value):
    """Patch the module-level builtin `hash` so smudging is deterministic."""
    return mock.patch.object(M, "hash", create=True, side_effect=lambda s: value)


def shamir(a0, a1, xs):
    return [(x, (a0 + a1 * x) % WAD) for x in xs]


class TestSmudgingDeterministic(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(M.SMUDGING_BOUND, 10 ** 12)
        self.assertEqual(M.WAD, 10 ** 18)

    def test_noise_range_and_formula(self):
        p = 500000000000000000
        cases = [(0, p - B), (B, p), (2 * B - 1, p + B - 1), (2 * B, p - B), (1, p - B + 1),
                 (-1, p + B - 1), (10 ** 30 + 5, p + (10 ** 30 + 5) % (2 * B) - B)]
        for h, want in cases:
            with with_hash(h):
                self.assertEqual(inject_smudging_noise(p), want, h)

    def test_hash_receives_decimal_string_of_input(self):
        with with_hash(B) as m:
            inject_smudging_noise(12345)
        m.assert_called_once_with("12345")

    def test_result_wraps_modulo_wad(self):
        with with_hash(0):
            self.assertEqual(inject_smudging_noise(5), WAD + 5 - B)
            self.assertEqual(inject_smudging_noise(0), WAD - B)
        with with_hash(2 * B - 1):
            self.assertEqual(inject_smudging_noise(WAD - 1), B - 2)
        with with_hash(B):
            self.assertEqual(inject_smudging_noise(WAD + 7), 7)

    def test_noise_is_bounded_for_real_hash(self):
        for p in (0, 1, 123456789, WAD - 1):
            out = inject_smudging_noise(p)
            diff = (out - p + WAD // 2) % WAD - WAD // 2
            self.assertTrue(-B <= diff < B)


class TestCombineDeterministic(unittest.TestCase):
    def test_insufficient_shares_message_and_boundary(self):
        with self.assertRaises(ValueError) as cm:
            combine_partial_decryptions([(1, 1)], 2)
        self.assertEqual(str(cm.exception), "Insufficient shares for quorum decryption.")
        with self.assertRaises(ValueError):
            combine_partial_decryptions([], 1)
        self.assertEqual(combine_partial_decryptions([(1, 9)], 1), 9)

    def test_two_of_n_recovers_constant_term(self):
        for a0, a1 in ((42, 7), (WAD - 1, WAD - 1), (0, 5), (10 ** 17, 3)):
            self.assertEqual(combine_partial_decryptions(shamir(a0, a1, [1, 2]), 2), a0)
            self.assertEqual(combine_partial_decryptions(shamir(a0, a1, [2, 1]), 2), a0)
            self.assertEqual(combine_partial_decryptions(shamir(a0, a1, [1, 4]), 2), a0)
            self.assertEqual(combine_partial_decryptions(shamir(a0, a1, [9, 2]), 2), a0)

    def test_lagrange_weights_for_ids_1_2(self):
        self.assertEqual(combine_partial_decryptions([(1, 10), (2, 4)], 2), 16)     # 2*y1 - y2
        self.assertEqual(combine_partial_decryptions([(1, 0), (2, 5)], 2), WAD - 5)
        self.assertEqual(combine_partial_decryptions([(1, 5), (2, 0)], 2), 10)

    def test_only_first_threshold_shares_are_used(self):
        good = shamir(42, 7, [1, 2])
        self.assertEqual(combine_partial_decryptions(good + [(3, 999)], 2), 42)
        self.assertEqual(combine_partial_decryptions(good + [(5, 1), (9, 2)], 2), 42)

    def test_single_share_threshold_one_scales_by_one(self):
        self.assertEqual(combine_partial_decryptions([(3, 77), (4, 5)], 1), 77)
        self.assertEqual(combine_partial_decryptions([(3, WAD + 77)], 1), 77)

    def test_reconstruction_result_is_reduced_mod_wad(self):
        got = combine_partial_decryptions([(1, WAD - 1), (2, WAD - 1)], 2)
        self.assertEqual(got, WAD - 1)
        self.assertTrue(0 <= combine_partial_decryptions([(1, 3 * WAD), (2, 5)], 2) < WAD)

    def test_known_defect_composite_modulus_rejects_threshold_three(self):
        """WAD = 10^18 is not prime: any 3 integer ids contain a pair with an even gap, so some
        Lagrange denominator is not invertible. The module raises instead of reconstructing."""
        g = lambda x: (42 + 7 * x + 9 * x * x) % WAD
        for ids in ([1, 2, 3], [1, 3, 5], [1, 4, 7], [2, 4, 6]):
            with self.assertRaises(ValueError):
                combine_partial_decryptions([(x, g(x)) for x in ids], 3)
        with self.assertRaises(ValueError):                      # threshold 2, even gap
            combine_partial_decryptions(shamir(42, 7, [1, 3]), 2)

    @unittest.expectedFailure
    def test_desired_behaviour_three_of_five_reconstruction(self):
        g = lambda x: (42 + 7 * x + 9 * x * x) % WAD
        self.assertEqual(combine_partial_decryptions([(x, g(x)) for x in (1, 2, 3)], 3), 42)


if __name__ == "__main__":
    unittest.main()
