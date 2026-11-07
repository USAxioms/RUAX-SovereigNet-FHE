"""FHE-WAD18 rev 3: leveled BFV (t = 2) with ciphertext x ciphertext multiplication,
relinearisation, and an encrypted solvency comparator (zero dependencies, integer-only).

Bits are encrypted as BFV ciphertexts over R_Q = Z_Q[x]/(x^N + 1), Q = 2^K, t = 2:
XOR is ciphertext addition, AND is multiplication + relinearisation. Integers are
little-endian bit vectors; adders, a 3:2 compressor and a comparator are Boolean
circuits evaluated through a pluggable backend (real ciphertexts, plain bits,
bound-only, depth-only). Every ciphertext carries a public worst-case noise bound
derived below; a result whose bound reaches DELTA/2 is flagged, never trusted.

Noise bound for a product (t = 2, ct phases c0 + c1 s = DELTA m + v + Q r with
|r| <= R = N//2 + 2 because coefficients are kept centred; m a constant bit):
    v_mul <= (1 + 2 N R)(v1 + v2) + ceil(2 N v1 v2 / Q) + ceil((N^2 + N + 1)/2)
             + L N (W/2) B
(the terms are: m v' + m' v, 2 r v' + 2 r' v, 2 v v'/Q, rounding of the three
scaled tensor components against 1, s, s^2, and relinearisation noise).

PARAMETERS ARE TOY-SIZED (N = 8): no security claim. Leveled only: no bootstrapping.
No floats, no '/' operator, no math/decimal/fractions imports.
"""
import hashlib
from collections import namedtuple

WAD = 10 ** 18
EV_WAD = 3_000_000_000 * WAD
CAP_NUM, CAP_DEN = 9, 20            # 45.000000000000000000 % = 9/20 exactly
BRK_NUM, BRK_DEN = 12, 25           # 48.000000000000000000 % = 12/25 exactly
ERR_BOUND = 3
WBITS = 32

Res = namedtuple("Res", "ok value reason")


def _ok(value):
    return Res(True, value, "")


def _fail(reason):
    return Res(False, None, reason)


# ------------------------------------------------------------------ randomness
class Drbg(object):
    def __init__(self, seed, label):
        self._seed = seed + b"|" + label.encode()
        self._ctr = 0
        self._buf = b""

    def bytes(self, n):
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._seed + b"|" + str(self._ctr).encode()).digest()
            self._ctr += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def uniform(self, modulus_bits):
        n = (modulus_bits + 7) // 8 + 8
        return int.from_bytes(self.bytes(n), "big") % (1 << modulus_bits)

    def ternary(self):
        return int.from_bytes(self.bytes(2), "big") % 3 - 1

    def small(self):
        b = self.bytes(1)[0]
        return (bin(b & 7).count("1")) - (bin((b >> 3) & 7).count("1"))


# ------------------------------------------------------------------ parameters
class Params(object):
    def __init__(self, n, k):
        self.n = n
        self.k = k
        self.q = 1 << k
        self.delta = self.q >> 1
        self.half_delta = self.delta >> 1
        self.r = n // 2 + 2
        self.fresh = ERR_BOUND * (2 * n + 1)
        self.w = 1 << WBITS
        self.l = k // WBITS + 1
        self.relin = self.l * n * (self.w >> 1) * ERR_BOUND
        self.rounding = (n * n + n + 2) // 2


def mul_bound(p, v1, v2):
    return ((v1 + v2) * (1 + 2 * p.n * p.r)
            + (2 * p.n * v1 * v2 + p.q - 1) // p.q
            + p.rounding + p.relin)


def centre(x, q):
    x = x % q
    return x - q if x > (q >> 1) else x


# ------------------------------------------------------------------ ring ops
def zmul(a, b, n):
    """Exact negacyclic product over Z."""
    out = [0] * n
    for i in range(n):
        x = a[i]
        if x == 0:
            continue
        for j in range(n):
            y = b[j]
            if y == 0:
                continue
            k = i + j
            if k < n:
                out[k] += x * y
            else:
                out[k - n] -= x * y
    return out


def qmul(a, b, p):
    return [centre(c, p.q) for c in zmul(a, b, p.n)]


def qadd(a, b, p):
    return [centre(a[i] + b[i], p.q) for i in range(p.n)]


def decompose(c, p):
    """Balanced base-W digits of each coefficient of the centred poly c.
    Returns list of p.l digit polys with sum_j d_j W^j == c exactly."""
    digits = [[0] * p.n for _ in range(p.l)]
    half = p.w >> 1
    for i in range(p.n):
        x = c[i]
        for j in range(p.l):
            r = x % p.w
            if r > half:
                r -= p.w
            digits[j][i] = r
            x = (x - r) // p.w
    return digits


# ----------------------------------------------------------------- ciphertext
class Ciphertext(object):
    __slots__ = ("c0", "c1", "nb")

    def __init__(self, c0, c1, nb):
        self.c0 = tuple(c0)
        self.c1 = tuple(c1)
        self.nb = nb

    def to_dict(self):
        return {"c0": list(self.c0), "c1": list(self.c1), "n": self.nb}

    @staticmethod
    def from_dict(d):
        return Ciphertext(d["c0"], d["c1"], d["n"])

    def __eq__(self, other):
        return (isinstance(other, Ciphertext) and self.c0 == other.c0
                and self.c1 == other.c1 and self.nb == other.nb)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.c0, self.c1, self.nb))


def ct_trivial(p, bit):
    c0 = [0] * p.n
    c0[0] = bit * p.delta
    return Ciphertext([centre(c, p.q) for c in c0], [0] * p.n, 0)


def ct_xor(p, x, y):
    return Ciphertext(qadd(x.c0, y.c0, p), qadd(x.c1, y.c1, p), x.nb + y.nb)


def ct_not(p, x):
    c0 = list(x.c0)
    c0[0] = centre(c0[0] + p.delta, p.q)
    return Ciphertext(c0, x.c1, x.nb)


def ct_and(p, evk, x, y):
    t0 = zmul(x.c0, y.c0, p.n)
    a = zmul(x.c0, y.c1, p.n)
    b = zmul(x.c1, y.c0, p.n)
    t1 = [a[i] + b[i] for i in range(p.n)]
    t2 = zmul(x.c1, y.c1, p.n)

    def scale(poly):          # round(2 * poly / Q) = floor(poly / DELTA + 1/2)
        return [centre((2 * c + p.delta) // (2 * p.delta), p.q) for c in poly]

    s0, s1, s2 = scale(t0), scale(t1), scale(t2)
    out0, out1 = s0, s1
    for j, d in enumerate(decompose(s2, p)):
        bj, aj = evk[j]
        out0 = qadd(out0, qmul(d, bj, p), p)
        out1 = qadd(out1, qmul(d, aj, p), p)
    return Ciphertext(out0, out1, mul_bound(p, x.nb, y.nb))


# ------------------------------------------------------------------- key side
class Public(object):
    """Public material: the encryption key and the relinearisation key."""

    def __init__(self, p, b, a, evk):
        self.p = p
        self.b = tuple(b)
        self.a = tuple(a)
        self.evk = tuple((tuple(x), tuple(y)) for x, y in evk)


class Encryptor(object):
    def __init__(self, pub, seed):
        self.pub = pub
        self._seed = seed
        self._used = set()

    def encrypt_bit(self, bit, label):
        p = self.pub.p
        if bit not in (0, 1):
            return _fail("NOT_A_BIT")
        if label in self._used:
            return _fail("LABEL_REUSE")
        self._used.add(label)
        d = Drbg(self._seed, "enc|" + label)
        u = [d.ternary() for _ in range(p.n)]
        e1 = [d.small() for _ in range(p.n)]
        e2 = [d.small() for _ in range(p.n)]
        c0 = qadd(qmul(list(self.pub.b), u, p), e1, p)
        c0[0] = centre(c0[0] + bit * p.delta, p.q)
        c1 = qadd(qmul(list(self.pub.a), u, p), e2, p)
        return _ok(Ciphertext(c0, c1, p.fresh))

    def encrypt_int(self, value, bits, label):
        if value < 0 or value >> bits:
            return _fail("VALUE_OUT_OF_RANGE")
        out = []
        for i in range(bits):
            r = self.encrypt_bit((value >> i) & 1, label + ":" + str(i))
            if not r.ok:
                return r
            out.append(r.value)
        return _ok(out)


class KeyHolder(object):
    def __init__(self, p, seed):
        self.p = p
        d = Drbg(seed, "keygen")
        self._s = [d.ternary() for _ in range(p.n)]
        a = [d.uniform(p.k) for _ in range(p.n)]
        e = [d.small() for _ in range(p.n)]
        a = [centre(c, p.q) for c in a]
        b = qadd([centre(-c, p.q) for c in qmul(a, self._s, p)], e, p)
        s2 = zmul(self._s, self._s, p.n)
        evk = []
        for j in range(p.l):
            aj = [centre(d.uniform(p.k), p.q) for _ in range(p.n)]
            ej = [d.small() for _ in range(p.n)]
            bj = qmul(aj, self._s, p)
            bj = [centre(-c, p.q) for c in bj]
            bj = qadd(bj, ej, p)
            shifted = [centre(c * (p.w ** j), p.q) for c in s2]
            bj = qadd(bj, shifted, p)
            evk.append((bj, aj))
        self.public = Public(p, b, a, evk)

    def _phase(self, ct):
        sc1 = qmul(list(ct.c1), self._s, self.p)
        return qadd(list(ct.c0), sc1, self.p)

    def decrypt_bit(self, ct):
        x = self._phase(ct)[0]
        r = (x + self.p.half_delta) // self.p.delta
        return r % 2

    def noise(self, ct):
        worst = 0
        for x in self._phase(ct):
            r = (x + self.p.half_delta) // self.p.delta
            e = x - r * self.p.delta
            e = -e if e < 0 else e
            if e > worst:
                worst = e
        return worst


class Decryptor(object):
    """The only party holding the secret key; logs what it is asked to open."""

    def __init__(self, keyholder):
        self._kh = keyholder
        self.query_log = []

    def open(self, ct):
        self.query_log.append("open")
        return self._kh.decrypt_bit(ct)


# ------------------------------------------------------------- op backends
class _W(object):
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v


class PlainOps(object):
    """Wires are Python ints 0/1. Every gate folds to a plain bit operation in the
    gate layer, so this backend deliberately has NO gate methods: any call that
    reached it would be a folding bug and fail loudly in the tests."""


class RealOps(object):
    def __init__(self, pub):
        self.p = pub.p
        self.evk = pub.evk
        self.exhausted = False
        self.ands = 0

    def _chk(self, ct):
        if ct.nb >= self.p.half_delta:
            self.exhausted = True
        return ct

    def xor(self, a, b):
        return self._chk(ct_xor(self.p, a, b))

    def and_(self, a, b):
        self.ands += 1
        return self._chk(ct_and(self.p, self.evk, a, b))

    def not_(self, a):
        return ct_not(self.p, a)

    def lift(self, w):
        if isinstance(w, int):
            return ct_trivial(self.p, w)
        return w


class BoundOps(object):
    def __init__(self, p):
        self.p = p
        self.ands = 0
        self.xors = 0
        self.nots = 0

    def fresh(self):
        return _W(self.p.fresh)

    def xor(self, a, b):
        self.xors += 1
        return _W(a.v + b.v)

    def and_(self, a, b):
        self.ands += 1
        return _W(mul_bound(self.p, a.v, b.v))

    def not_(self, a):
        self.nots += 1
        return _W(a.v)


class DepthOps(object):
    def __init__(self):
        self.ands = 0
        self.xors = 0
        self.nots = 0

    def fresh(self):
        return _W(0)

    def xor(self, a, b):
        self.xors += 1
        return _W(max(a.v, b.v))

    def and_(self, a, b):
        self.ands += 1
        return _W(max(a.v, b.v) + 1)

    def not_(self, a):
        self.nots += 1
        return _W(a.v)


# ------------------------------------------------- constant-folding gate layer
def g_xor(ops, a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a ^ b
    if isinstance(a, int):
        return b if a == 0 else ops.not_(b)
    if isinstance(b, int):
        return a if b == 0 else ops.not_(a)
    return ops.xor(a, b)


def g_and(ops, a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a & b
    if isinstance(a, int):
        return 0 if a == 0 else b
    if isinstance(b, int):
        return 0 if b == 0 else a
    return ops.and_(a, b)


def g_not(ops, a):
    if isinstance(a, int):
        return 1 - a
    return ops.not_(a)


# ------------------------------------------------------------------- circuits
def pad(bits, width):
    return list(bits) + [0] * (width - len(bits))


def shift(bits, amount):
    return [0] * amount + list(bits)


def add2(ops, a, b, width):
    """Kogge-Stone adder; both inputs padded to width; result truncated to width."""
    a, b = pad(a, width), pad(b, width)
    pp = [g_xor(ops, a[i], b[i]) for i in range(width)]
    gg = [g_and(ops, a[i], b[i]) for i in range(width)]
    gp = list(pp)
    d = 1
    while d < width:
        ng, np_ = list(gg), list(gp)
        for i in range(d, width):
            ng[i] = g_xor(ops, gg[i], g_and(ops, gp[i], gg[i - d]))
            if i >= 2 * d:
                np_[i] = g_and(ops, gp[i], gp[i - d])
        gg, gp = ng, np_
        d *= 2
    out = []
    for i in range(width):
        carry = 0 if i == 0 else gg[i - 1]
        out.append(g_xor(ops, pp[i], carry))
    return out


def csa(ops, a, b, c, width):
    """3:2 compressor: returns (sum, carry<<1), both of the given width."""
    a, b, c = pad(a, width), pad(b, width), pad(c, width)
    s, cy = [], [0]
    for i in range(width):
        axb = g_xor(ops, a[i], b[i])
        s.append(g_xor(ops, axb, c[i]))
        maj = g_xor(ops, g_and(ops, axb, g_xor(ops, a[i], c[i])), a[i])
        cy.append(maj)
    return s, cy[:width]


def sum_parts(ops, parts, width):
    parts = [pad(x, width)[:width] for x in parts]
    while len(parts) > 2:
        s, cy = csa(ops, parts[0], parts[1], parts[2], width)
        parts = parts[3:] + [s, cy]
    if len(parts) == 2:
        return add2(ops, parts[0], parts[1], width)
    if len(parts) == 1:
        return parts[0]
    return [0] * width


def mul_const(ops, bits, const, width):
    parts = []
    i = 0
    while (const >> i) != 0:
        if (const >> i) & 1:
            parts.append(shift(bits, i))
        i += 1
    return sum_parts(ops, parts, width)


def less_than(ops, a, b, width):
    """Unsigned a < b on little-endian bit vectors."""
    a, b = pad(a, width), pad(b, width)
    nodes = []
    for i in range(width):
        lt = g_and(ops, g_not(ops, a[i]), b[i])
        eq = g_not(ops, g_xor(ops, a[i], b[i]))
        nodes.append((lt, eq))
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes) - 1, 2):
            lo, hi = nodes[i], nodes[i + 1]
            lt = g_xor(ops, hi[0], g_and(ops, hi[1], lo[0]))
            eq = g_and(ops, hi[1], lo[1])
            nxt.append((lt, eq))
        if len(nodes) % 2:
            nxt.append(nodes[-1])
        nodes = nxt
    return nodes[0][0]


def over_ratio(ops, debt, ev, num, den, width):
    """True iff debt/ev > num/den, i.e. den*debt > num*ev (exact, integer)."""
    lhs = mul_const(ops, debt, den, width)
    rhs = mul_const(ops, ev, num, width)
    return less_than(ops, rhs, lhs, width)


def solvency_flags(ops, debt, ev):
    """(over_cap, over_breaker) wires for little-endian bit vectors debt, ev."""
    width = max(len(debt), len(ev)) + 6
    over_cap = over_ratio(ops, debt, ev, CAP_NUM, CAP_DEN, width)
    over_brk = over_ratio(ops, debt, ev, BRK_NUM, BRK_DEN, width)
    return over_cap, over_brk


def to_bits(value, width):
    return [(value >> i) & 1 for i in range(width)]


def choose_k(n, bits):
    """Smallest K (multiple of 32) whose worst-case bound fits the comparator."""
    k = 64
    while True:
        p = Params(n, k)
        ops = BoundOps(p)
        d = [ops.fresh() for _ in range(bits)]
        e = [ops.fresh() for _ in range(bits)]
        wires = solvency_flags(ops, d, e)
        worst = max(w.v for w in wires if not isinstance(w, int))
        if worst < p.half_delta:
            return k
        k += 32


def attest(pub, debt_cts, ev_cts):
    """Operator side: evaluates both flags on ciphertexts using ONLY public
    material. Returns Res((cap_ct, brk_ct), ...) or HEADROOM_EXHAUSTED."""
    ops = RealOps(pub)
    cap, brk = solvency_flags(ops, debt_cts, ev_cts)
    if ops.exhausted:
        return _fail("HEADROOM_EXHAUSTED")
    return _ok((ops.lift(cap), ops.lift(brk)))
