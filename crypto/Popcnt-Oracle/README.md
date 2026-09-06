# Popcnt Oracle — Crypto

**Event:** Black Hat MEA CTF Qualification 2026 (FlagYard)

**Category:** Crypto

**Author:** FlagYard

**Flag:** `BHFlagY{f2bfc77b60aa990dc06ef4e1830c578e}`

> *Poping Shower!*

---

## Challenge

The handout contains a short RSA service:

```python
import os
from Crypto.Util.number import getPrime
from math import gcd
import secrets

flag = os.environ.get("DYN_FLAG", "BHFlagY{dummy}")

e = 65537
while True:
    p = getPrime(1024)
    q = getPrime(1024)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q
d = pow(e, -1, (p-1)*(q-1))
m = secrets.randbelow(n)
c = pow(m, e, n)

print(f"{e = }")
print(f"{n = }")
print(f"{c = }")
while True:
    x = int(input("x> "))
    if x == m:
        print(flag)
        break
    print(pow(x, d, n).bit_count())
```

The server prints an RSA public key and `c = m^e mod n`. We win only by submitting the exact
random 2048-bit plaintext `m`. Every wrong guess is decrypted and the server returns the
population count — the number of one bits — of that plaintext.

At first glance, one Hamming weight seems far too weak to recover a 2048-bit integer. The missing
piece is textbook RSA's multiplicative structure: the oracle does not have to receive guesses for
`m`; it can receive encryptions of chosen multiples of `m`.

## 1. Turning RSA into a chosen-multiple oracle

For any chosen multiplier `r`, send

```text
x = c * r^e mod n
```

RSA decryption gives

```text
x^d = (m^e * r^e)^d = m*r mod n.
```

The returned value is therefore

```text
HW(m*r mod n),
```

where `HW` denotes Hamming weight. Choosing `r = 2^i` exposes the orbit

```text
a_i = m * 2^i mod n.
```

Consecutive values satisfy

```text
a_(i+1) = 2*a_i                 if a_i < n/2
a_(i+1) = 2*a_i - n             if a_i >= n/2.
```

If no reduction occurs, doubling is only a left shift, so its Hamming weight is preserved exactly:

```text
a_i < n/2  =>  HW(a_(i+1)) = HW(a_i).
```

A changed Hamming weight consequently proves that `a_i` was in the upper half. The converse is not
always true: subtracting `n` can occasionally produce a result with the same Hamming weight. Those
collisions are the main technical problem in the challenge.

## 2. Why the upper-half decisions recover `m`

Write the binary expansion of the fraction `m/n` as

```text
m/n = 0.b_0 b_1 b_2 ... (base 2).
```

The modular-doubling map is the binary shift map. Its upper-half decision at step `i` is exactly
the next binary digit:

```text
b_i = floor(2*a_i/n).
```

After `L = bit_length(n)` decisions, the prefix `P` bounds the secret to

```text
P / 2^L <= m/n < (P+1) / 2^L.
```

Equivalently,

```text
ceil(n*P / 2^L) <= m <= ceil(n*(P+1) / 2^L) - 1.
```

Because `n < 2^L`, this interval has width below one. Once the decisions are correct, it contains
at most one integer, which is the exact `m`.

## 3. Detecting both halves with the negative orbit

To make the upper-half test reliable, query both a value and its modular negative. If

```text
z_i = -a_i mod n = n-a_i,
```

then `z_i` occupies the opposite half of the residue interval. Exactly one of the two doubling
steps performs a modular subtraction:

| Positive stream | Negative stream | Decision |
|---|---|---|
| Hamming weight changes | unchanged | `a_i >= n/2`, so `b_i = 1` |
| unchanged | Hamming weight changes | `a_i < n/2`, so `b_i = 0` |
| unchanged | unchanged | popcount collision; mark an erasure |

Both streams cannot change on the same step. The stream that does not reduce is a plain left shift,
whose Hamming weight is guaranteed to remain equal.

In the winning instance, this classified all but 18 of the 2048 decisions. The remaining positions
were erasures, never incorrect bits.

## 4. Reducing the number of expensive oracle calls

A direct implementation would query every positive and every negative value, costing about 4098
RSA private operations. The remote service is CPU-bound and instances can expire, so the exploit
uses an adaptive shortcut.

First, it collects the complete positive stream. It then queries `HW(n-m)` once and walks forward:

* If the positive weight changes, the decision is `1`. The negative side did not reduce, so its next
  weight equals its current weight and no query is needed.
* If the positive weight stays equal, the exploit asks only for the next negative weight. A change
  identifies `0`; equality identifies a collision.

The live run required:

```text
2049 positive observations
1030 adaptive negative observations
```

That reduced the main collection from roughly 4100 to 3079 private RSA operations.

## 5. Resolving the remaining collisions

The 18 erased decisions still represent up to `2^18` prefixes. A second orbit with multiplier
`r = 3` resolves them without collecting another complete stream:

```text
a_i^(3) = 3*m*2^i mod n.
```

Only the samples adjacent to the erased primary positions are queried. The solver performs a
depth-first reconstruction of the binary prefix of `m/n`. At depth `k`, a prefix `P` fixes

```text
m/n in [P/2^k, (P+1)/2^k).
```

For a secondary constraint at shift `i`, the fractional value

```text
frac(3 * 2^i * m/n)
```

lies in a correspondingly small interval. As soon as that interval lies entirely below or above
`1/2`, its upper-half bit is determined. Any branch that disagrees with the observed `r = 3` label
is discarded immediately.

One `r = 3` position also collided in the winning run, so the exploit added a single sparse
`r = 5` check. The search then explored only 2067 prefix nodes — essentially one path through the
2048 decisions — and recovered a unique integer.

## 6. Crafting the RSA queries

The exploit never encrypts a plaintext directly. Starting from `c`, it updates ciphertexts with
public operations:

```python
double_cipher = pow(2, e, n)
value = c

for _ in range(n.bit_length() + 1):
    positive_query = value
    negative_query = (-value) % n
    value = (value * double_cipher) % n
```

Decrypting `positive_query` yields `m*2^i mod n`; decrypting `negative_query` yields its modular
negative. The same construction with `c * 3^e mod n` and `c * 5^e mod n` creates the sparse
secondary streams.

## 7. Recovering and submitting the plaintext

For every surviving `L`-bit prefix, the solver computes the exact integer interval:

```python
low = ceil(n * prefix / 2**L)
high = ceil(n * (prefix + 1) / 2**L) - 1
```

A candidate is accepted only when `low == high` and its entire positive doubling orbit reproduces
the recorded Hamming weights. The resulting integer is sent to the same socket as a decimal value.
This final input satisfies `x == m`, so the service prints the flag instead of decrypting it.

## Winning run

```text
[*] Connected: n is 2048 bits, e = 65537
[*] Collecting 2049 positive observations
[*] Collecting 1030 adaptive negative observations
[*] Primary stream has 18 collisions; resolving only those
[*] 1 secondary collisions remain; adding r = 5
[*] primary erasures: 18; multipliers: [1, 3, 5]
[*] explored 2067 prefix nodes
[*] Plaintext recovered; submitting it
BHFlagY{f2bfc77b60aa990dc06ef4e1830c578e}}
```

The deployed service printed one extra closing brace. Removing that deployment artifact gives the
normal FlagYard wrapper:

```text
BHFlagY{f2bfc77b60aa990dc06ef4e1830c578e}
```

The complete transcript is preserved in [`artifacts/session.txt`](artifacts/session.txt).

## Reproduction

Start a fresh instance, then run:

```bash
cd crypto/Popcnt-Oracle
python3 solve/exploit.py tcp.flagyard.com PORT --timeout 90
```

The live service may need several minutes to answer all queries. The exploit keeps one connection
open because each new connection generates a different RSA key and plaintext.

No third-party Python packages are needed by the exploit. The original challenge server requires
PyCryptodome only for RSA prime generation.

## Files

```text
artifacts/
  popcnt_oracle.tar.gz.zip  untouched downloaded handout
  popcnt_oracle.tar.gz      inner challenge archive
  prob.py                   extracted challenge source
  session.txt               successful live transcript
solve/
  exploit.py                batched adaptive network client
  popcnt_solver.py          collision-resistant prefix recovery
```
