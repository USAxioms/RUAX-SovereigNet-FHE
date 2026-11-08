import unittest
from unittest import mock

from src import dkg_wad18 as D
from src.dkg_wad18 import DKGNode, WAD

class TestDKG(unittest.TestCase):
    def test_share_generation_and_evaluation(self):
        node = DKGNode(node_id=1, threshold=3, total_nodes=5)
        shares = node.generate_shares()
        self.assertEqual(len(shares), 5)
        self.assertTrue(all(0 <= val < WAD for _, val in shares))

    def test_node_share_accumulation(self):
        nodes = [DKGNode(i, threshold=3, total_nodes=5) for i in range(1, 6)]
        for sender in nodes:
            shares = sender.generate_shares()
            for receiver_id, val in shares:
                nodes[receiver_id - 1].receive_share(sender.node_id, val)

        final_shares = [node.compute_final_secret_share() for node in nodes]
        self.assertEqual(len(final_shares), 5)


def make_node(coeffs, node_id=1, total=5):
    """DKGNode whose secret polynomial coefficients are exactly `coeffs` (randomness patched)."""
    it = iter(coeffs)
    with mock.patch.object(D.secrets, "randbelow", side_effect=lambda n: next(it)) as m:
        node = DKGNode(node_id, len(coeffs), total)
    return node, m


class TestDKGDeterministic(unittest.TestCase):
    def test_constant_is_exactly_wad(self):
        self.assertEqual(WAD, 1000000000000000000)
        self.assertIs(type(WAD), int)
        self.assertEqual(D.WAD, WAD)

    def test_constructor_state_and_randomness_calls(self):
        node, m = make_node([5, 7, 11], node_id=4, total=9)
        self.assertEqual((node.node_id, node.threshold, node.total_nodes), (4, 3, 9))
        self.assertEqual(node.coefficients, [5, 7, 11])
        self.assertEqual(node.received_shares, [])
        self.assertEqual(m.call_args_list, [mock.call(WAD)] * 3)

    def test_received_shares_not_shared_between_nodes(self):
        a, _ = make_node([1, 2])
        b, _ = make_node([3, 4])
        a.receive_share(1, 9)
        self.assertEqual(b.received_shares, [])

    def test_evaluate_polynomial_horner_order_and_values(self):
        node, _ = make_node([5, 7, 11])
        self.assertEqual(node.evaluate_polynomial(0), 5)
        self.assertEqual(node.evaluate_polynomial(1), 23)
        self.assertEqual(node.evaluate_polynomial(2), 5 + 14 + 44)
        self.assertEqual(node.evaluate_polynomial(10), 5 + 70 + 1100)
        self.assertEqual(node.evaluate_polynomial(WAD + 3), node.evaluate_polynomial(3))

    def test_evaluate_polynomial_wraps_mod_wad_at_every_step(self):
        node, _ = make_node([WAD - 1, WAD - 1, WAD - 1])
        self.assertEqual(node.evaluate_polynomial(2), WAD - 7)         # -(1 + 2 + 4)
        self.assertEqual(node.evaluate_polynomial(1), WAD - 3)
        big, _ = make_node([0, 0, 1])
        self.assertEqual(big.evaluate_polynomial(10 ** 10), 0)          # 10^20 mod 10^18
        self.assertEqual(big.evaluate_polynomial(10 ** 9 + 1), (10 ** 9 + 1) ** 2 % WAD)

    def test_single_coefficient_is_constant(self):
        node, _ = make_node([77])
        for x in (0, 1, 5, WAD):
            self.assertEqual(node.evaluate_polynomial(x), 77)

    def test_generate_shares_ids_values_and_count(self):
        node, _ = make_node([5, 7, 11], total=4)
        self.assertEqual(node.generate_shares(), [(1, 23), (2, 63), (3, 5 + 21 + 99), (4, 5 + 28 + 176)])
        one, _ = make_node([5, 7, 11], total=1)
        self.assertEqual(one.generate_shares(), [(1, 23)])
        none, _ = make_node([5, 7, 11], total=0)
        self.assertEqual(none.generate_shares(), [])

    def test_receive_share_appends_in_order(self):
        node, _ = make_node([1])
        node.receive_share(3, 30)
        node.receive_share(1, 10)
        self.assertEqual(node.received_shares, [(3, 30), (1, 10)])

    def test_final_share_sums_mod_wad(self):
        node, _ = make_node([1])
        self.assertEqual(node.compute_final_secret_share(), 0)
        node.receive_share(1, WAD - 1)
        node.receive_share(2, 5)
        self.assertEqual(node.compute_final_secret_share(), 4)
        node.receive_share(3, WAD)
        self.assertEqual(node.compute_final_secret_share(), 4)

    def test_final_share_is_evaluation_of_summed_polynomial(self):
        polys = [[5, 7, 11], [WAD - 2, 3, 4], [100, 200, WAD - 5]]
        nodes = [make_node(c, node_id=i + 1, total=3)[0] for i, c in enumerate(polys)]
        for sender in nodes:
            for rid, val in sender.generate_shares():
                nodes[rid - 1].receive_share(sender.node_id, val)
        summed = [sum(c[k] for c in polys) % WAD for k in range(3)]
        ref, _ = make_node(summed)
        for node in nodes:
            self.assertEqual(node.compute_final_secret_share(), ref.evaluate_polynomial(node.node_id))

    def test_unpatched_randomness_stays_in_range(self):
        node = DKGNode(1, 4, 6)
        self.assertEqual(len(node.coefficients), 4)
        self.assertTrue(all(0 <= c < WAD for c in node.coefficients))
        self.assertTrue(all(0 <= v < WAD for _, v in node.generate_shares()))

    def test_coefficients_come_from_secrets_not_a_constant(self):
        a, b = DKGNode(1, 5, 5), DKGNode(1, 5, 5)
        self.assertNotEqual(a.coefficients, b.coefficients)         # 2^-299 false-failure chance


if __name__ == "__main__":
    unittest.main()
