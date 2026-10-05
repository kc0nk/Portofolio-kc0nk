# Dovetail

## Flag

`Null0rigin{the_loader_never_read_the_label}`

## Solve

Dovetail uses the same five-layer cascade as Cinder, but its sources include a guided PNG walk and a raw PNG chunk/CRC calculation. The important detail is to model the loader's actual byte-level behavior instead of trusting semantic labels. The solver rebuilds all source hashes, verifies each key commitment, solves the GF(2) systems, and checks all intermediate vectors against the final flag.

## Reproduce

Run `exploits/solve_dovetail.py`; recovered layer material is in `exploits/dovetail-layers.json`.

