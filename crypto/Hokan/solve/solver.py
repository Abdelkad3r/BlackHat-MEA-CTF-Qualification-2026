"""Full Hokan solver.

f is a 5-term polynomial in 11 variables of degree <= 11 over F_p, p a secret
256-bit prime.  We get 8 evaluations.  Ben-Or/Tiwari would need 2*5 = 10 -- and
we don't even know p -- so the queries are split:

  queries 1..7   v^(i) = (z^(i*w_0), ..., z^(i*w_10)),  i = 0..6
                 => a_i = sum_j c_j (z^K_j)^i,  K_j = <w, e_j> in [0, 33].
                 The BOT roots are now tiny and depend only on the multiset
                 {K_j}, so we can enumerate all C(34,5) supports.  Each guess
                 gives an exact integer annihilator; for the true one the two
                 shifted relations are exact multiples of p, and their gcd is p.
                 Then a Vandermonde solve gives the coefficients c_j.

  query 8        v = (2,3,5,...,31).  Now y = sum_j c_j m_j (mod p) with
                 m_j = prod prime_i^e_ji < 2^55 -- a low-density modular
                 knapsack in 5 unknowns, solved by lattice reduction.  Factor
                 each m_j over the primes to read off the exponent vector.
"""
from itertools import combinations
from math import gcd
from fractions import Fraction
import sim

NV = 11
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
W = (0, 3, 1, 2, 3, 0, 2, 1, 3, 2, 1)     # max 3 -> K in [0,33]
Z = 2
TERMS = 5

# ---------------------------------------------------------------- phase 1
def phase1_points():
    return [[pow(Z, i * wi) for wi in W] for i in range(7)]

def find_p(a, minbits=200):
    R = NV * max(W)
    roots = [Z**k for k in range(R + 1)]
    A0 = [a[5 - k] for k in range(6)]
    A1 = [a[6 - k] for k in range(6)]
    hits = []

    def dfs(start, depth, poly, Ks):
        if depth == TERMS:
            R0 = A0[0]*poly[0] + A0[1]*poly[1] + A0[2]*poly[2] + A0[3]*poly[3] + A0[4]*poly[4] + A0[5]*poly[5]
            R1 = A1[0]*poly[0] + A1[1]*poly[1] + A1[2]*poly[2] + A1[3]*poly[3] + A1[4]*poly[4] + A1[5]*poly[5]
            g = gcd(R0 if R0 > 0 else -R0, R1 if R1 > 0 else -R1)
            if g.bit_length() >= minbits:
                hits.append((g, tuple(Ks)))
            return
        for k in range(start, R + 1 - (TERMS - depth - 1)):
            r = roots[k]
            np_ = [poly[0]]
            for i in range(1, depth + 1):
                np_.append(poly[i] - r * poly[i - 1])
            np_.append(-r * poly[depth])
            Ks.append(k)
            dfs(k + 1, depth + 1, np_, Ks)
            Ks.pop()

    dfs(0, 0, [1], [])
    out = []
    for g, Ks in hits:
        for q in range(2, 100000):
            while g % q == 0 and (g // q).bit_length() >= minbits:
                g //= q
        if g > max(a) and sim.is_prime(g):
            out.append((g, Ks))
    return out

def solve_coeffs(a, Ks, p):
    n = len(Ks)
    r = [pow(Z, k, p) for k in Ks]
    M = [[pow(r[j], i, p) for j in range(n)] + [a[i] % p] for i in range(n)]
    for col in range(n):
        piv = next((i for i in range(col, n) if M[i][col] % p), None)
        if piv is None: return None
        M[col], M[piv] = M[piv], M[col]
        inv = pow(M[col][col], -1, p)
        M[col] = [x * inv % p for x in M[col]]
        for i in range(n):
            if i != col and M[i][col]:
                fac = M[i][col]
                M[i] = [(x - fac * y) % p for x, y in zip(M[i], M[col])]
    cs = [M[i][n] for i in range(n)]
    # A zero amplitude means the guessed support carries a root the polynomial
    # does not actually have, i.e. the true {K_j} had fewer than TERMS distinct
    # values.  Such an instance is unrecoverable -- reject and reconnect.
    if any(c % p == 0 for c in cs):
        return None
    for i in range(n, len(a)):          # verify against the unused evaluations
        if sum(c * pow(rj, i, p) for c, rj in zip(cs, r)) % p != a[i] % p:
            return None
    return cs

# ---------------------------------------------------------------- lattice
def lll(B, delta=Fraction(99, 100)):
    B = [list(map(int, row)) for row in B]
    n = len(B)
    def gso(B):
        mu = [[Fraction(0)] * n for _ in range(n)]
        Bs, nrm = [], []
        for i in range(n):
            v = [Fraction(x) for x in B[i]]
            for j in range(i):
                if nrm[j]:
                    mu[i][j] = sum(Fraction(B[i][k]) * Bs[j][k] for k in range(len(B[i]))) / nrm[j]
                    v = [a - mu[i][j] * b for a, b in zip(v, Bs[j])]
            Bs.append(v)
            nrm.append(sum(x * x for x in v))
        return mu, nrm
    mu, nrm = gso(B)
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            q = mu[k][j]
            r = int(q + Fraction(1, 2)) if q >= 0 else -int(-q + Fraction(1, 2))
            if r:
                B[k] = [a - r * b for a, b in zip(B[k], B[j])]
                mu, nrm = gso(B)
        if nrm[k] >= (delta - mu[k][k-1] ** 2) * nrm[k - 1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            mu, nrm = gso(B)
            k = max(k - 1, 1)
    return B

def babai(B, t):
    """Nearest-plane: closest lattice point to t for an LLL-reduced basis B."""
    n = len(B)
    Bs, mu = [], [[Fraction(0)] * n for _ in range(n)]
    nrm = []
    for i in range(n):
        v = [Fraction(x) for x in B[i]]
        for j in range(i):
            if nrm[j]:
                mu[i][j] = sum(Fraction(B[i][k]) * Bs[j][k] for k in range(len(B[i]))) / nrm[j]
                v = [a - mu[i][j] * b for a, b in zip(v, Bs[j])]
        Bs.append(v); nrm.append(sum(x*x for x in v))
    b = [Fraction(x) for x in t]
    coef = [0]*n
    for i in range(n - 1, -1, -1):
        if not nrm[i]: continue
        c = sum(b[k] * Bs[i][k] for k in range(len(b))) / nrm[i]
        ci = int(c + Fraction(1, 2)) if c >= 0 else -int(-c + Fraction(1, 2))
        coef[i] = ci
        b = [x - ci * Fraction(y) for x, y in zip(b, B[i])]
    out = [0]*len(t)
    for i in range(n):
        if coef[i]:
            out = [o + coef[i]*B[i][k] for k, o in enumerate(out)]
    return out

def solve_knapsack(cs, y, p, bounds=None):
    """Find small m_j > 0 with sum cs_j*m_j = y (mod p).

    L = {x in Z^5 : sum cs_j x_j = 0 mod p} has determinant p, so by the
    Gaussian heuristic lambda_1(L) ~ p^(1/5) ~ 2^51.  A genuine solution has
    m_j ~ 2^37 (a degree-<=11 monomial over the first 11 primes), i.e. norm
    ~2^40 << lambda_1/2, so the closest vector is unique and Babai finds it.
    Uniform scaling is essential here: weighting by the per-K worst case
    (31^11) skews the basis badly and the reduction misses the target.
    """
    n = len(cs)
    piv = next((i for i in range(n) if cs[i] % p), None)
    if piv is None:
        return []
    ipv = pow(cs[piv], -1, p)
    basis = [[0]*n for _ in range(n)]
    basis[piv][piv] = p
    for j in range(n):
        if j == piv: continue
        basis[j][piv] = (-ipv * cs[j]) % p
        basis[j][j] = 1
    t = [0]*n
    t[piv] = (ipv * y) % p
    red = lll(basis)
    u = babai(red, t)
    cands = [[t[i] - u[i] for i in range(n)]]
    # a couple of neighbours in case Babai lands one cell off
    for bi in range(n):
        for s in (1, -1):
            cands.append([t[i] - u[i] - s*red[bi][i] for i in range(n)])
    return cands

# ---------------------------------------------------------------- monomials
def factor_monomial(m):
    e = [0]*NV
    for i, q in enumerate(PRIMES):
        while m % q == 0:
            m //= q; e[i] += 1
    return (tuple(e) if m == 1 else None)

def sage_str(pairs, p):
    """Sage's repr: degrevlex descending, vars joined by '*', coeff omitted if 1."""
    def key(ce):
        e = ce[1]
        return (sum(e), tuple(-e[i] for i in reversed(range(NV))))
    out = []
    for c, e in sorted(pairs, key=key, reverse=True):
        multi = "*".join(f"x{i}" + (f"^{ei}" if ei != 1 else "")
                         for i, ei in enumerate(e) if ei)
        if not multi:            out.append(str(c % p))
        elif c % p == 1:         out.append(multi)
        elif c % p == p - 1:     out.append("-" + multi)
        else:                    out.append(f"{c % p}*{multi}")
    return " + ".join(out).replace(" + -", " - ")

# ---------------------------------------------------------------- driver
_KMAX = None
def kmax_table():
    global _KMAX
    if _KMAX is None:
        _KMAX = {}
        for e in sim.all_monomials():
            k = sum(a*b for a, b in zip(W, e))
            v = 1
            for q, ei in zip(PRIMES, e):
                if ei: v *= q**ei
            if v > _KMAX.get(k, 0): _KMAX[k] = v
    return _KMAX

def solve(a7, y8, verbose=True):
    cands = find_p(a7)
    if verbose: print(f"  phase1: {len(cands)} candidate (p,K) pairs")
    for p, Ks in cands:
        cs = solve_coeffs(a7, Ks, p)
        if cs is None: continue
        if verbose: print(f"  p={p}\n  K={Ks}")
        for ms in solve_knapsack(cs, y8, p):
            pairs = []
            ok = True
            for c, k, m in zip(cs, Ks, ms):
                if m <= 0: ok = False; break
                e = factor_monomial(m)
                if e is None or sum(e) > NV or sum(a*b for a, b in zip(W, e)) != k:
                    ok = False; break
                pairs.append((c, e))
            if ok and sum(c * m for c, m in zip(cs, ms)) % p == y8 % p:
                return p, pairs
    return None
