# Hokan — Crypto

**Event:** Black Hat MEA CTF Qualification 2026 (FlagYard)
**Category:** Crypto
**Flag:** `BHFlagY{b76085b3a7563a438da13397e0a8da14}`

> *…Wait, 8 queries?*

---

## Challenge

```python
import os

flag = os.environ.get("DYN_FLAG", "BHFlagY{dummy}")
R = PolynomialRing(Zmod(random_prime(2^256)), 11, "x")
f = R.random_element(degree=11)

for _ in range(8):
    v = list(map(int, input("> ").split(",")))
    print(f(*v))
if str(f) == input("> "):
    print(flag)
```

Eleven variables, degree ≤ 11, a secret 256-bit prime modulus, **eight** evaluations, and you
must reproduce `str(f)` character for character.

*Hokan* (補間) is Japanese for **interpolation** — the title is the hint.

## Why eight is the whole puzzle

Sage's `MPolynomialRing_base.random_element` defaults to `terms=5`:

```python
if terms is None:
    if total >= 5:
        terms = 5
```

so `f` is a **5-term** polynomial. Its monomials are drawn uniformly from all
`binomial(22,11) = 705432` monomials of degree ≤ 11 in 11 variables.

Ben-Or/Tiwari sparse interpolation needs `2t = 10` evaluations for a 5-sparse polynomial. We
have 8. And we don't even know `p`, which every step of the arithmetic requires.

Two obstacles, one budget. Counting the information, though, it is not hopeless:

| unknown | bits |
|---|---|
| `p` | 256 |
| 5 coefficients in `[0,p)` | 1280 |
| 5 monomials out of 705432 | 97 |
| **needed** | **1633** |
| available: 8 × log₂ p | **2048** |

So a solution exists — it just cannot be a generic sparse-interpolation algorithm. It has to
exploit the fact that the exponents live in a *small, known* set.

## Recon

Two things are worth establishing before writing any maths.

**The service takes ~28 s to answer.** That is Sage starting up. My first probe used a 6-second
timeout and the service looked dead:

```
no data after 1 query: timed out
```

**`p` and `f` are freshly random on every connection.** Sending an identical query set down two
connections gives two unrelated answer sets, so there is no accumulating queries across
sessions — everything must come out of one session's eight.

```
conn A   [1]*11 -> 5226873945499952041655581879930230104947917304629601989945508053246873836890
conn B   [1]*11 -> 4503185451316233031895676066163918853382130671604280503563490454449330237958
```

Usefully, the attack below turns out to be **fully non-adaptive**: all eight points are fixed in
advance, so we can fire them off, close our eyes, compute for a few seconds, and only then send
the answer. No round-trip pressure.

Two free observations from the probe: `f(0,…,0) = 0` (no constant term) and `f(1,0,…,0) = 0`
(no pure power of `x0`) — consistent with 5 monomials drawn from 705432.

---

## The idea: a weighted-degree substitution

Evaluate along a geometric family built from a **weight vector** `w`:

```
v⁽ⁱ⁾ = ( z^(i·w₀), z^(i·w₁), …, z^(i·w₁₀) )
```

A monomial `x^e` then collapses to a single power of `z`:

```
∏ₖ (z^(i·wₖ))^eₖ  =  z^(i·⟨w,e⟩)
```

so the evaluations form a Ben-Or/Tiwari sequence

```
aᵢ = f(v⁽ⁱ⁾) = Σⱼ cⱼ · (z^Kⱼ)ⁱ ,      Kⱼ = ⟨w, eⱼ⟩
```

whose roots `z^Kⱼ` are **tiny** and depend only on the multiset `{Kⱼ}`. That is the whole trick:
it converts "which 5 of 705432 monomials?" into "which 5 values of `⟨w,e⟩`?", and the latter
is small enough to enumerate exhaustively.

### Choosing `w` — a measured trade-off

The weighted degree ranges over `[0, 11·max(w)]`, so the support search costs
`C(11·max(w)+1, 5)`. Bigger `w` spreads the `Kⱼ` apart (good: we need them **distinct**, or two
monomials' coefficients merge and the instance is lost) but blows up the search. I measured
both sides over 4000 random 5-monomial samples rather than guessing:

| `w` | K range | supports `C(R+1,5)` | 5 distinct `Kⱼ` |
|---|---:|---:|---:|
| all ones (plain total degree) | 11 | 792 | **0.8 %** |
| max 2 | 22 | 33 649 | 42.1 % |
| max 3 | 33 | 278 256 | 52.9 % |
| **max 3, spread** `(0,3,1,2,3,0,2,1,3,2,1)` | **33** | **278 256** | **56.0 %** |
| max 4 | 44 | 1 221 759 | 64.7 % |
| max 5 | 55 | 3 819 816 | 66.1 % |
| max 7 | 77 | 21 111 090 | 75.4 % |

**Plain total degree is useless** — 0.8 %. Half of all monomials of degree ≤ 11 have degree
*exactly* 11 (`C(21,11)/C(22,11) = 0.5`), and another 26 % have degree 10, so five random
monomials essentially always collide on degree. Anything that reduces `f` to its degree profile
throws the coefficients into merged buckets and cannot be undone.

`max 3, spread` is the sweet spot: 278 k supports searches in ~4 s, and 56 % of instances are
solvable. The rest fail cleanly and we reconnect.

---

## Phase 1 — queries 1–7: recover `p` and the coefficients

Send `v⁽ⁱ⁾` for `i = 0..6`, giving `a₀ … a₆`.

For a **guessed** support `{K₁ … K₅}` the roots `z^Kⱼ` are known exactly, so we can build the
annihilating polynomial over the *integers*:

```
Λ(Z) = ∏ⱼ (Z − z^Kⱼ) = Σₖ Eₖ Z^(5−k)     (E₀ = 1, all Eₖ ∈ ℤ)
```

Because `Λ` kills every root of the sequence, each shifted relation

```
Rᵢ = Σₖ Eₖ · a_(i+5−k)      i = 0, 1
```

is an exact **multiple of `p`** — computed entirely in ℤ from public numbers. Two of them are
enough:

```
gcd(R₀, R₁) = p · gcd(κ₀, κ₁)
```

and `gcd(κ₀,κ₁)` is tiny, so stripping small factors and testing primality (plus `p > max aᵢ`)
recovers `p` outright. A wrong support gives two essentially random ~2⁴²⁴ integers whose gcd is
small, so the true support announces itself. In practice exactly one candidate survives.

The search is a DFS that extends `Λ` one root at a time, reusing prefixes, so each of the
278 256 leaves costs 12 big-int multiplications and one gcd — about 4 seconds in pure Python.

With `p` and the `Kⱼ` in hand, the amplitudes fall out of a Vandermonde solve on `a₀…a₄`, and
`a₅, a₆` — deliberately held back — **verify** the result.

```
phase1: 1 candidate (p,K) pairs
p=22506639698101281076962449818093261022858920674767227711431485102684443458397
K=(9, 14, 18, 19, 21)
```

> **Degenerate supports.** If the true `{Kⱼ}` has a collision (only 4 distinct values), many
> size-5 supersets annihilate the sequence and phase 1 returns ~30 candidates, each with a zero
> amplitude. That is the signal to give up on this instance and reconnect. My first live run
> crashed here on `pow(cs[0], -1, p)`; the fix is to reject any solve with a zero amplitude and
> to pivot on an invertible coefficient rather than assuming `c₀` is one.

---

## Phase 2 — query 8: a low-density modular knapsack

One query left, and five monomials still to pin down. Evaluate at the **first eleven primes**:

```
v = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
y = Σⱼ cⱼ·mⱼ  (mod p),      mⱼ = ∏ᵢ primeᵢ^(eⱼᵢ)
```

The prime basis makes `e ↦ m` injective, and — crucially — **small**. A degree-≤11 monomial
over these primes averages about 2³⁷ (worst case `31¹¹ ≈ 2⁵⁴·⁵`), so the five unknowns total
~190 bits against a 256-bit modulus. That is a *low-density* knapsack, hence lattice territory.

Consider

```
L = { x ∈ ℤ⁵ : Σⱼ cⱼxⱼ ≡ 0 (mod p) }
```

`L` has determinant `p`, so by the Gaussian heuristic `λ₁(L) ≈ p^(1/5) ≈ 2⁵¹`. Our target has
norm ≈ 2⁴⁰ — comfortably inside `λ₁/2`, so the closest vector is **unique** and Babai's
nearest-plane on an LLL-reduced basis finds it. Take any particular solution `t` of the
congruence, solve CVP, and read off `m = t − u`.

> **The one real trap.** My first attempt scaled each coordinate by its per-`K` *worst case*
> (`31¹¹` for some classes, far less for others). That skews the basis so badly the reduction
> misses the target, and every instance failed with "density 1.06". **Uniform scaling** is
> correct here: the bounds are unknown anyway, and the true solution is short enough that the
> unweighted lattice already isolates it.

Finally, trial-divide each `mⱼ` by the eleven primes to read off the exponent vector `eⱼ`
directly, and check `Σeⱼ ≤ 11` and `⟨w,eⱼ⟩ = Kⱼ`.

Note that the congruence check `Σ cⱼmⱼ ≡ y` is *vacuous* — every point of the coset satisfies
it. The real verification is that each `mⱼ` factors completely over the eleven primes with the
right weighted degree; a wrong lattice point differs by ≈ 2⁵¹ and has no chance of doing that.

---

## Reproducing `str(f)` exactly

Getting the polynomial right is not the end — the string has to match byte for byte. Sage's
`MPolynomial_polydict.__repr__` delegates to `PolyDict.poly_repr`, which:

* joins variables with `*`, writing `^k` only when `k ≠ 1` → `x0*x1^2*x10^4`
* omits a unit coefficient entirely, and renders `p−1` as a leading `-`
* joins terms with `" + "`, then applies `.replace(" + -", " - ")`
* sorts by the term order's sortkey with `reverse=True`

The ring's default order is **degrevlex**, whose sortkey in Sage is

```python
def sortkey_degrevlex(self, f):
    return (sum(f.nonzero_values(sort=False)), tuple(reversed([-v for v in f])))
```

i.e. `(total_degree, (−e₁₀, −e₉, …, −e₀))`, descending. Ties at equal degree therefore go to
the **smaller trailing exponent** first.

This detail cost me a debugging round: my first local model used a sloppier ordering, so the
solver's (correct) output was reported as a mismatch even though every coefficient and monomial
was right. The lesson is that the reference implementation has to be the thing under test too.

---

## Results

Because there is no oracle to check against mid-session, everything was developed against a
local model of the challenge (`solve/sim.py`) — random 256-bit prime, five uniformly-chosen
monomials, Sage-accurate `str()`.

```
$ python3 solve/bigtest.py
25 instances in 65s: solved=14 K-collision=11 other-fail=0
=> per-connection success ~56%
```

**Zero failures** whenever the five weighted degrees are distinct — the 44 % loss is entirely
the collision case, which is detected and returns cleanly so the driver reconnects
(`solve/collision_test.py` asserts that collisions never raise and never return a wrong answer).

Live, it landed on attempt 4:

```
=== attempt 4 ===
  [+] booted in 28s
  [+] 8 queries done (29s), solving...
  phase1: 1 candidate (p,K) pairs
  p=22506639698101281076962449818093261022858920674767227711431485102684443458397
  K=(9, 14, 18, 19, 21)
  [+] f = 11009932442512469248347420817634832509228818476313118764625225966755293183552*x1^2*x2^2*x4*x5^2*x8^3*x10 + …

*** BHFlagY{b76085b3a7563a438da13397e0a8da14} ***
```

Full transcript in [`artifacts/session.txt`](artifacts/session.txt).

## Takeaways

**Pick the substitution so the unknowns land in a set you can enumerate.** Ben-Or/Tiwari treats
the monomial values as arbitrary field elements and pays `2t` evaluations for the privilege.
Here the exponents were known to be tiny, and a weight vector converts that knowledge into
BOT roots drawn from a 34-element set — which is what buys the two missing queries.

**An unknown modulus is recoverable whenever you can build an exact integer annihilator.** Any
relation among the outputs that must vanish mod `p`, but is computable over ℤ, is a multiple of
`p`; two of them and a gcd is all it takes. Guessing cheap structure (the support) to
manufacture that relation is the move.

**Measure the parameter you are about to guess.** The weight vector looked like a free choice.
It is the difference between a 0.8 % and a 56 % success rate, and five minutes of sampling
settled it.

---

## Reproducing

```bash
cd solve
python3 pick_w.py           # the weight-vector trade-off table
python3 bigtest.py          # end-to-end success rate against the local model
python3 collision_test.py   # collisions fail cleanly, never wrongly
python3 exploit.py          # live: retries until an instance is solvable
```

Pure Python 3, no third-party packages — LLL, Babai, Miller-Rabin and the Sage-accurate
`str()` are all implemented in `solve/`.

## Layout

```
solve/
  solver.py          the attack: phase-1 support search, Vandermonde solve,
                     LLL + Babai knapsack, monomial factoring, Sage str()
  sim.py             local model of the challenge (for offline development)
  client.py          socket client (handles the ~28 s Sage boot)
  exploit.py         driver: 8 non-adaptive queries, solve, answer, retry
  pick_w.py          measures distinctness vs search cost per weight vector
  bigtest.py         success rate over random instances
  collision_test.py  asserts collisions fail cleanly
artifacts/
  prob.sage          the challenge source
  session.txt        the winning session transcript
```
