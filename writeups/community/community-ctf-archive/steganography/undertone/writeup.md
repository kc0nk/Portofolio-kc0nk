# Undertone

## Flag

`Null0rigin{the_order_of_the_colours_is_the_message}`

## Solve

The previous stage's full flag seeds a pseudorandom audio carrier. Correlating the waveform with that keyed carrier in 2048-sample blocks yields one bit per block. Packing those bits reconstructs the CRC32-valid flag record and share `55c2e79140ab3d08`.

## Exploits

Run `exploits/solve_undertone.py`; the probe and recovered metadata are included alongside it.

