# Stillwater

User: `Null0rigin{you_rode_the_cycle_instead_of_reading_it}`

Root: `Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}`

Recovered through read-only inspection of the supplied OVA and offline reconstruction of its seal routine. No live VM exploitation was performed.

The damaged public survey image retains the personnel extract, credential standard and fragment A: `e94837b2225e9dbf`. The binary level log consists of 96-byte records; the anomalous record with level -788 contains fragment B, `b685186c466bd2ce`. The privileged seal fragment is `d70f14ea164169a1`.

The personnel record constrains the root password to the Wellflash52 family. Checking the finite candidate set against the SHA512crypt hash recovers `Wellflash52199%`. The chain input is Blackdamp's root flag, `Null0rigin{you_paid_for_every_candidate}`.

The user and root files contain ciphertext followed by a 32-byte integrity tag. The reverse-engineered stream consists of SHA256(key || "ks" || big-endian counter), beginning at zero. SHA256(key || "tag" || plaintext) verifies both recovered flags. `solve_stillwater.py` reconstructs the domain-separated keys, decrypts both seals and checks those tags before writing `stillwater-results.json`.

The boot and timed-code checks are execution gates and do not contribute to the encryption keys. The mounted-disk decoy is excluded.
