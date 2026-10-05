# Mordant

## Flag

`Null0rigin{he_set_two_sorts_where_one_would_do}`

## Solve

Parse the original PNG scanlines rather than only the rendered pixels. Filter choices encode two bits each, with filter 4 treated as equivalent to filter 0. The encoded stream is XORed with both a card-key stream and a stream keyed by SHA-256 of the six earlier shares. Removing both streams produces a CRC32-valid flag record.

## Exploit

`exploits/solve_mordant.py` implements the PNG filter-channel decoder and keyed unmasking.

