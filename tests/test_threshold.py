import unittest
import bfv_wad18 as B
import threshold_bfv as T

N, BITS = 64, 4
K0 = B.choose_k(N, BITS)
K = K0 + 64      # extra modulus bits are the smudging budget (40 bits + margin)


class TestThreshold(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = B.Params(N, K)
        cls.kh = B.KeyHolder(cls.p, b"thr-seed")
        cls.pub = cls.kh.public
        cls.enc = B.Encryptor(cls.pub, b"thr-enc")
        cls.parties = T.split_key(cls.kh, 3, b"split")
        cls.i = 0

    def fresh(self, v):
        TestThreshold.i += 1
        return self.enc.encrypt_bit(v, "x%d" % TestThreshold.i).value

    def test_shares_sum_to_secret(self):
        p = self.p
        acc = [0] * p.n
        for party in self.parties:
            acc = [acc[i] + party._share[i] for i in range(p.n)]
        self.assertEqual([B.centre(c, p.q) for c in acc], self.kh._s)

    def test_combined_matches_single_key_decrypt_on_flags(self):
        for party in self.parties:
            party.allowed.clear()
        D = self.enc.encrypt_int(10, BITS, "d").value
        E = self.enc.encrypt_int(15, BITS, "e").value
        r = B.attest(self.pub, D, E)
        self.assertTrue(r.ok)
        for ct in r.value:
            for party in self.parties:
                party.authorise(T.ct_digest(ct))
        got = [T.threshold_open(self.p, ct, self.parties, "f%d" % j).value for j, ct in enumerate(r.value)]
        want = [self.kh.decrypt_bit(ct) for ct in r.value]
        self.assertEqual(got, want)
        self.assertEqual(got, [int(20 * 10 > 9 * 15), int(25 * 10 > 12 * 15)])

    def test_party_refuses_unauthorised_ciphertext(self):
        ct = self.fresh(1)                      # an INPUT ciphertext, never authorised
        r = T.threshold_open(self.p, ct, self.parties, "bad")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "NOT_AUTHORISED")
        for party in self.parties:
            self.assertNotIn(T.ct_digest(ct), party.opened)

    def test_one_missing_party_cannot_decrypt(self):
        ok_wrong = 0
        trials = 24
        for v in [0, 1] * (trials // 2):
            ct = self.fresh(v)
            for party in self.parties:
                party.authorise(T.ct_digest(ct))
            parts = [party.partial(ct, "m%d" % self.i).value for party in self.parties[:-1]]
            r = T.combine(self.p, ct, parts)
            if r.ok and r.value == v:
                ok_wrong += 1
        self.assertLess(ok_wrong, trials)       # missing share => essentially a coin flip, not all correct

    def test_smudging_noise_is_large_and_bounded(self):
        ct = self.fresh(1)
        for party in self.parties:
            party.authorise(T.ct_digest(ct))
        parts = [party.partial(ct, "s%d" % self.i).value for party in self.parties]
        for poly, bound in parts:
            self.assertEqual(bound, ct.nb << T.SMUDGE_BITS)
        total = ct.nb + sum(b for _, b in parts)
        self.assertLess(total, self.p.half_delta)

    def test_headroom_failure_closes(self):
        p = B.Params(N, 96)
        kh = B.KeyHolder(p, b"small")
        ps = T.split_key(kh, 2, b"sp")
        ct = B.Encryptor(kh.public, b"se").encrypt_bit(1, "a").value
        big = B.Ciphertext(ct.c0, ct.c1, p.half_delta >> 10)
        for q in ps:
            q.authorise(T.ct_digest(big))
        r = T.threshold_open(p, big, ps, "h")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")

    def test_minimal_modulus_fails_closed_for_threshold_open(self):
        p = B.Params(N, K0)                      # comparator fits, smudging does not
        kh = B.KeyHolder(p, b"min")
        enc = B.Encryptor(kh.public, b"min-e")
        r = B.attest(kh.public, enc.encrypt_int(10, BITS, "d").value, enc.encrypt_int(15, BITS, "e").value)
        self.assertTrue(r.ok)
        ps = T.split_key(kh, 3, b"mm")
        res = []
        for j, ct in enumerate(r.value):
            for q in ps:
                q.authorise(T.ct_digest(ct))
            res.append(T.threshold_open(p, ct, ps, "m%d" % j))
        self.assertIn("HEADROOM_EXHAUSTED", [x.reason for x in res if not x.ok])

    def test_smudge_is_actually_added_and_within_bound(self):
        ct = self.fresh(1)
        party = self.parties[0]
        party.authorise(T.ct_digest(ct))
        part, bound = party.partial(ct, "smudge-check").value
        clean = B.qmul(list(ct.c1), party._share, self.p)
        e = [B.centre(part[i] - clean[i], self.p.q) for i in range(self.p.n)]
        worst = max(abs(x) for x in e)
        self.assertGreater(worst, ct.nb << 20)      # far above the ciphertext's own noise
        self.assertLessEqual(worst, bound)

    def test_open_is_logged_per_party(self):
        ct = self.fresh(0)
        for party in self.parties:
            party.authorise(T.ct_digest(ct))
        before = [len(q.opened) for q in self.parties]
        T.threshold_open(self.p, ct, self.parties, "log")
        for q, b in zip(self.parties, before):
            self.assertEqual(len(q.opened), b + 1)
            self.assertEqual(q.opened[-1], T.ct_digest(ct))

    def test_combine_rejects_when_total_noise_reaches_half_delta(self):
        ct = self.fresh(1)
        ph = [0] * self.p.n
        r = T.combine(self.p, ct, [(ph, self.p.half_delta)])
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        ok = T.combine(self.p, ct, [(ph, 0)])
        self.assertTrue(ok.ok)

    def test_party_itself_refuses_oversized_smudge(self):
        ct = self.fresh(1)
        big = B.Ciphertext(ct.c0, ct.c1, self.p.half_delta >> 10)
        party = self.parties[0]
        party.authorise(T.ct_digest(big))
        r = party.partial(big, "big")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "HEADROOM_EXHAUSTED")
        self.assertNotIn(T.ct_digest(big), party.opened)

    def test_deterministic(self):
        ct = self.fresh(1)
        for party in self.parties:
            party.authorise(T.ct_digest(ct))
        a = self.parties[0].partial(ct, "same").value
        b = self.parties[0].partial(ct, "same").value
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
