"""Local model of the Hokan challenge, so the attack can be developed offline."""
import random

NVARS, DEG = 11, 11

def is_prime(n, rounds=32):
    if n < 2: return False
    for q in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % q == 0: return n == q
    d, r = n-1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(rounds):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(r-1):
            x = x*x % n
            if x == n-1: break
        else:
            return False
    return True

def random_prime(bits=256):
    while True:
        c = random.getrandbits(bits) | 1
        if c > 3 and is_prime(c): return c

_MONS = None
def all_monomials(n=NVARS, d=DEG):
    """Every exponent vector with total degree <= d (705432 for n=d=11)."""
    global _MONS
    if _MONS is not None: return _MONS
    out = []
    def rec(i, rem, cur):
        if i == n - 1:
            for e in range(rem + 1):
                out.append(tuple(cur) + (e,))
            return
        for e in range(rem + 1):
            cur.append(e); rec(i+1, rem-e, cur); cur.pop()
    rec(0, d, [])
    _MONS = out
    return out

class Chal:
    def __init__(self, terms=5, p=None, seed=None):
        if seed is not None: random.seed(seed)
        self.p = p or random_prime()
        mons = all_monomials()
        self.mons = random.sample(mons, terms)
        self.coeffs = [random.randrange(1, self.p) for _ in self.mons]
        self.n = 0
    def eval(self, v):
        assert len(v) == NVARS
        self.n += 1
        tot = 0
        for c, e in zip(self.coeffs, self.mons):
            t = c
            for vi, ei in zip(v, e):
                if ei: t = t * pow(vi, ei, self.p) % self.p
            tot = (tot + t) % self.p
        return tot % self.p
    def sage_str(self):
        """Mirror of Sage's MPolynomial_polydict.__repr__.

        PolyDict.poly_repr joins variables with '*', drops a unit coefficient,
        and sorts by the term order's sortkey with reverse=True.  For the
        default degrevlex that key is
            (total_degree, tuple(reversed([-e_0, ..., -e_{n-1}])))
        i.e. ties at equal degree go to the smaller trailing exponent first.
        """
        def key(ce):
            e = ce[1]
            return (sum(e), tuple(-e[i] for i in reversed(range(NVARS))))
        out = []
        for c, e in sorted(zip(self.coeffs, self.mons), key=key, reverse=True):
            multi = "*".join(f"x{i}" + (f"^{ei}" if ei != 1 else "")
                             for i, ei in enumerate(e) if ei)
            if not multi:              out.append(str(c % self.p))
            elif c % self.p == 1:      out.append(multi)
            elif c % self.p == self.p - 1: out.append("-" + multi)
            else:                      out.append(f"{c % self.p}*{multi}")
        return " + ".join(out).replace(" + -", " - ")

if __name__ == "__main__":
    import time
    t0 = time.time()
    m = all_monomials()
    print(f"monomials: {len(m)}  ({time.time()-t0:.1f}s)")
    c = Chal(seed=1)
    print("p =", c.p)
    print("mons =", c.mons)
    print("degrees =", [sum(e) for e in c.mons])
    print("f(1..1) =", c.eval([1]*11))
