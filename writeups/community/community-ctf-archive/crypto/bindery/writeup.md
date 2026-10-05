# Bindery

## Flag

`Null0rigin{you_counted_in_a_base_she_never_named}`

## Solve

The challenge's serialized values must be interpreted with the non-obvious radix implied by the record layout rather than as ordinary decimal fields. Reconstructing the intended integer sequence and using it in the supplied cryptographic transformation recovers the plaintext flag. The included solver contains the exact parsing, key derivation, and decryption path used during the solve.

## Reproduce

Run `exploits/solve_bindery.py` beside the original Bindery challenge directory.

