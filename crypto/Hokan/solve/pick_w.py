"""How often do 5 random monomials get distinct weighted degrees <w,e>?
Trade-off: the phase-1 support search costs C(11*max(w)+1, 5)."""
import random
from math import comb
import sim

mons = sim.all_monomials()
random.seed(7)
samples = [random.sample(mons, 5) for _ in range(4000)]

CANDS = {
    "ones            ": (1,)*11,
    "max2 0-1-2      ": (0,1,2,0,1,2,0,1,2,0,1),
    "max3 0..3       ": (0,1,2,3,0,1,2,3,0,1,2),
    "max3 spread     ": (0,3,1,2,3,0,2,1,3,2,1),
    "max4 0..4       ": (0,1,2,3,4,0,1,2,3,4,0),
    "max5 0..5       ": (0,1,2,3,4,5,0,1,2,3,4),
    "max7 0..7       ": (0,1,2,3,4,5,6,7,0,1,2),
}
print(f"{'w':18} {'R':>4} {'C(R+1,5)':>12} {'distinct%':>10}")
for name, w in CANDS.items():
    R = 11*max(w)
    d = sum(1 for s in samples if len({sum(a*b for a,b in zip(w,e)) for e in s}) == 5)
    print(f"{name} {R:>4} {comb(R+1,5):>12} {100*d/len(samples):>9.1f}%")
