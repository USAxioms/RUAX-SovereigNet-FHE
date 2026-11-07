import unittest
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

if __name__ == "__main__":
    unittest.main()
