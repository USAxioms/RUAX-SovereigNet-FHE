import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from src import sovereign_node as S

ZERO = "0x" + "0" * 64


class Clock(object):
    """Stand-in for time.time() with no float anywhere: int(Clock(n)) == n."""

    def __init__(self, seconds):
        self.seconds = seconds

    def __int__(self):
        return self.seconds


def at(seconds):
    return mock.patch.object(S.time, "time", return_value=Clock(seconds))


def canon_hash(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class TestSovereignNode(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        os.remove(self.path)
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    def test_constructor_state(self):
        d = S.SovereignNodeDaemon(7, self.path)
        self.assertEqual((d.node_id, d.ledger_path, d.current_state_hash), (7, self.path, ZERO))
        self.assertEqual(len(ZERO), 66)

    def test_state_hash_is_sha256_of_sorted_canonical_json(self):
        d = S.SovereignNodeDaemon(1, self.path)
        p = {"b": 2, "a": {"z": 1, "y": [3, 4]}}
        h = d.compute_wad18_state_hash(p)
        self.assertEqual(h, canon_hash(p))
        self.assertEqual(len(h), 64)
        self.assertFalse(h.startswith("0x"))
        self.assertEqual(h, d.compute_wad18_state_hash({"a": {"y": [3, 4], "z": 1}, "b": 2}))
        self.assertNotEqual(h, d.compute_wad18_state_hash({"a": {"y": [3, 5], "z": 1}, "b": 2}))

    def test_state_hash_does_not_mutate_state(self):
        d = S.SovereignNodeDaemon(1, self.path)
        d.compute_wad18_state_hash({"x": 1})
        self.assertEqual(d.current_state_hash, ZERO)
        self.assertFalse(os.path.exists(self.path))

    def test_step_commits_payload_and_chains_hashes(self):
        d = S.SovereignNodeDaemon(3, self.path)
        with at(1700000000):
            h1 = d.step_refinement_loop({"v": 1, "w": 2})
            h2 = d.step_refinement_loop({"v": 5})
        p1 = {"node_id": 3, "timestamp": 1700000000, "inputs": {"v": 1, "w": 2}, "prev_hash": ZERO}
        p2 = {"node_id": 3, "timestamp": 1700000000, "inputs": {"v": 5}, "prev_hash": h1}
        self.assertEqual(h1, canon_hash(p1))
        self.assertEqual(h2, canon_hash(p2))
        self.assertNotEqual(h1, h2)
        self.assertEqual(d.current_state_hash, h2)
        with open(self.path) as fh:
            raw = fh.read()
        self.assertTrue(raw.endswith("\n"))
        lines = raw.split("\n")[:-1]
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), {"hash": h1, "payload": p1})
        self.assertEqual(json.loads(lines[1]), {"hash": h2, "payload": p2})

    def test_timestamp_is_integer_seconds(self):
        d = S.SovereignNodeDaemon(1, self.path)
        with at(5):
            d.step_refinement_loop({})
        with open(self.path) as fh:
            rec = json.loads(fh.readline())
        self.assertEqual(rec["payload"]["timestamp"], 5)
        self.assertIs(type(rec["payload"]["timestamp"]), int)

    def test_appends_to_existing_file(self):
        with open(self.path, "w") as fh:
            fh.write("old line\n")
        d = S.SovereignNodeDaemon(1, self.path)
        d.step_refinement_loop({"a": 1})
        with open(self.path) as fh:
            lines = fh.read().split("\n")
        self.assertEqual(lines[0], "old line")
        self.assertEqual(len(lines), 3)

    def test_two_daemons_same_input_differ_by_node_id(self):
        a, b = S.SovereignNodeDaemon(1, self.path), S.SovereignNodeDaemon(2, self.path)
        with at(100):
            self.assertNotEqual(a.step_refinement_loop({"k": 1}), b.step_refinement_loop({"k": 1}))

    def test_known_defect_wall_clock_makes_commitments_irreproducible(self):
        d1, d2 = S.SovereignNodeDaemon(1, self.path), S.SovereignNodeDaemon(1, self.path)
        with at(100):
            h1 = d1.step_refinement_loop({"k": 1})
        with at(101):
            h2 = d2.step_refinement_loop({"k": 1})
        self.assertNotEqual(h1, h2)       # same inputs, different hash: breaks bit-for-bit parity


if __name__ == "__main__":
    unittest.main()
