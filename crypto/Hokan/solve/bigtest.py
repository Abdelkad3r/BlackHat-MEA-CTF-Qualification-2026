import random, time, sim, solver
random.seed(99)
wins = coll = fail = 0
N = 25
t0=time.time()
for i in range(N):
    c = sim.Chal()
    K = [sum(a*b for a,b in zip(solver.W,e)) for e in c.mons]
    if len(set(K)) != 5:
        coll += 1; continue
    a7 = [c.eval(v) for v in solver.phase1_points()]
    y8 = c.eval(solver.PRIMES)
    r = solver.solve(a7, y8, verbose=False)
    if r and solver.sage_str(r[1], r[0]) == c.sage_str(): wins += 1
    else: fail += 1
print(f"{N} instances in {time.time()-t0:.0f}s: solved={wins} K-collision={coll} other-fail={fail}")
print(f"=> per-connection success ~{100*wins/N:.0f}%")
