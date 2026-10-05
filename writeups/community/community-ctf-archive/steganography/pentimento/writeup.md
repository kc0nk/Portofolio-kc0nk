# Pentimento

## Flag

`Null0rigin{keep_the_grain_and_burn_the_chaff}`

## Solve

The carrier uses the ordering of palette-entry pairs. Canonically rank the colours, compare each pair's actual order to that rank, and pack the resulting bits. The authenticated output includes share `bd3f60a8e2749c15`.

## Exploit

`exploits/solve_pentimento.py` implements the palette ranking and extraction.

