# Quietus

## Flag

`Null0rigin{the_channel_closes_from_the_inside}`

## Solve

Parse the original DEFLATE stream. Whenever a prior three-byte sequence makes either representation legal, the encoder's choice between a literal and a length-three match carries a bit; matches always use the nearest occurrence. Decode those choices and remove the key stream derived from the Mordant flag to recover the final CRC32-valid record.

## Exploit

`exploits/solve_quietus.py` performs raw DEFLATE parsing and channel extraction.

