# Palimpsest

## Flag

`Null0rigin{the_table_wrote_itself_at_dawn}`

## Solve

The layer-source routine is emulated with Unicorn. Hooks replace hashing, allocation, copying, and the shadow-file read while the original challenge code performs the table logic. Each 32-byte source is fed into the shared cascade key schedule, checked against its embedded digest, and used to solve a GF(2) system. The fifth vector is the flag and the first four are cryptographically checked against it.

## Reproduce

Run `exploits/solve_palimpsest.py`; `exploits/palimpsest-layers.json` preserves all sources, keys, and solutions.

