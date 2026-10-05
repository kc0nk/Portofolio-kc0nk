# Revenant

## Flag

`Null0rigin{the_clone_never_reseeded_the_rng}`

## Solve

The two suspend images came from cloned state that reused the same pseudorandom stream. Aligning the related encrypted material and exploiting the repeated keystream recovered the plaintext flag. The final SHA-256 exactly matches the verifier's embedded digest.

## Reproduce

The principal recovery scripts are `exploits/open_revenant.py`, `exploits/revenant_more.py`, and `exploits/revenant_xor.py`. The recovered flag is saved in `exploits/19-revenant_flag.txt`.

