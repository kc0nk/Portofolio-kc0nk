# Quicklime

## Flag

`Null0rigin{you_kept_the_last_eleven_bits}`

## Solve

Each cascade source depends on exact floating-point behavior: x87 operations, precision control, FMA, and the low bits used to select a reduction-table entry. The solver executes only small locally authored instruction helpers to reproduce those semantics, hashes the selected table blocks, derives five keys, and solves the associated GF(2) matrices. Every selector digest and intermediate constraint is verified before the final ASCII flag is accepted.

## Reproduce

Run `exploits/solve_quicklime.py`; `exploits/quicklime-layers.json` records the verified solutions.

