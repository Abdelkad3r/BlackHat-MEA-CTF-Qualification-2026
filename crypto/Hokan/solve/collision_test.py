"""Instances whose weighted degrees collide must fail cleanly (return None),
not raise -- the driver relies on that to reconnect."""
import random, sim, solver
random.seed(31337)
seen = 0
for _ in range(60):
    c = sim.Chal()
    K = [sum(a*b for a,b in zip(solver.W,e)) for e in c.mons]
    if len(set(K)) == 5:
        continue
    seen += 1
    a7 = [c.eval(v) for v in solver.phase1_points()]
    y8 = c.eval(solver.PRIMES)
    try:
        r = solver.solve(a7, y8, verbose=False)
    except Exception as e:
        print(f"RAISED on collision instance: {type(e).__name__}: {e}"); raise
    assert r is None or solver.sage_str(r[1], r[0]) == c.sage_str(), "wrong answer returned!"
    if seen >= 12: break
print(f"{seen} collision instances: all handled cleanly (no exceptions, no wrong answers)")
