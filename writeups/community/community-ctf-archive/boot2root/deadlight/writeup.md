# Deadlight

User: `Null0rigin{the_lamp_told_you_by_going_out}`

Root: `Null0rigin{a_deadlight_is_a_reading_not_a_failure}`

This recovery uses read-only inspection of the supplied OVA and offline reconstruction of its seal routine. It does not claim a live VM exploitation run.

The real user flag is `/var/lib/lamp/user.txt`. The public signed-request sample and chroot contain decoys.

The personnel extract and credential standard constrain the root and seal credentials. The bench's SHA256 commitments recover `Chimneystem54449&` and `F0rdb0th0m94280#` from their finite candidate families. Both also independently verify against their SHA512crypt hashes.

The anomalous cap-21 record in `readings.db` contains a base64 note giving fragment B, `HX6IP`. The keeper's reserved list gives fragment C, `RF4SZ`. Instead of decoding the damaged firmware, `recover_seed.py` searches the six unknown base32 characters against `bench.conf`'s SHA256 seed commitment using OpenCL. It finds fragment A, `C4WSWU`, and verifies the full seed `C4WSWUHX6IPRF4SZ` again with Python's SHA256.

The chain input is Stillwater's root flag. Reverse engineering the `deadlight` executable gives:

```
key = SHA256(chain_flag || root_password || seal_phrase || seed)
block[0] = SHA256(key || "deadlight-seal")
block[i+1] = SHA256(block[i] || "deadlight-seal")
plaintext = sealed.bin XOR concatenated blocks
```

`solve_deadlight.py` verifies all four bench commitments, both credential hashes, the user file and the recovered root flag format before saving `deadlight-results.json`. The root ciphertext has no separate integrity tag; validation rests on the verified input commitments and the recovered flag plaintext. The boot and timed-code checks are program execution gates, not encryption-key inputs.

Run from the project directory with the Python environment containing pyopencl, numpy and passlib:

```
.venv\Scripts\python.exe ctf-deadlight\recover_seed.py
.venv\Scripts\python.exe ctf-deadlight\solve_deadlight.py
```
