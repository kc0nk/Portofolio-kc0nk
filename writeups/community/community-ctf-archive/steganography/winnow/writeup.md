# Winnow

## Flag

`Null0rigin{nothing_takes_until_it_is_fixed}`

## Solve

Each tile pair contains one authentic tile and one decoy. Validate the pair, select the authenticated tile, and extract its encoded bit. The CRC32-valid record also yields share `07e5cb3219d6f48b`.

## Exploit

`exploits/solve_winnow.py` performs tile authentication and bit recovery.

