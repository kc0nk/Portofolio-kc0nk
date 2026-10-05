# Moire

## Flag

`Null0rigin{a_carrier_laid_across_the_whole_room}`

## Solve

The message is encoded by choices between equal-weight cell patterns. Rows alternate traversal direction, so decoding every row left-to-right produces noise. Applying the serpentine order recovers the CRC32-valid record and share `f10983dd6b5ec4a2`.

## Exploits

Use `exploits/moire_probe.py` to identify the cell channel and `exploits/solve_moire_share.py` to recover the authenticated share.

