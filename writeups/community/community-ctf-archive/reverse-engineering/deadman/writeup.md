# Deadman

## Flag

`Null0rigin{you_held_it_exactly_right}`

## Solve

Deadman hides its five sources behind anti-debug and timing gates. The solver enumerates the small, bounded state spaces and selects the state whose derived key matches the binary's embedded digest. The intended states are tracer changes 3, slow page faults, the all-ones single-step mask, a slow busy loop, and timer mask `0xf0f0`. The resulting five GF(2) systems are full-rank; the final vector is the flag and all intermediate constraints verify.

## Reproduce

Run `exploits/solve_deadman.py`; see `exploits/deadman-layers.json` for the selected states and recovered vectors.

