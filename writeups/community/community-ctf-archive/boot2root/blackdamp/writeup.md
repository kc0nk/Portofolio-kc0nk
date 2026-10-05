# Blackdamp solution

Recovered and HMAC-verified flags:

- User: `Null0rigin{the_seam_number_was_two_of_the_four}`
- Root: `Null0rigin{you_paid_for_every_candidate}`

Bundle password: `bd-bridgebottom54322@`. Root password: `Drinkmere11257#`. Both match their stored SHA-512 crypt hashes. Assembled seed: `ea3f9e5bbda5c910f4c01df2`.

The host VM is `28-blackdamp.ova`. Its SHA-256 matches its bundled checksum:

`f058a444909ddd3ff6e8f6f37ac8c8b8c97676bff36e1f7c0452f268691d657b`

The parent `NullOrigin_Boot2Root_Chain.7z` also matches the published SHA-256:

`ac7f40cb560e0459d3e9b906b446cbc7d0fc656a71a916f77a5879463e8af863`

## Exposed status-page path

The monitor advertises `/status` and `/pit-records.tar`, authenticated by `X-Shift-Code`. The current hourly code is the first 16 bytes of HMAC-SHA256 of the decimal UTC epoch hour, keyed by the plant key as ASCII text, rendered as 32 lower-case hex characters. Its notice points to an exposed OTA service on port 8088.

The lamp firmware is `/var/lib/blackdampd/lamp-fw.img`. Its container gives a little-endian payload offset and length at offsets 8 and 12. The bench note describes damaged SquashFS magic and length fields. Repair the payload's first four bytes to `hsqs`, and restore its eight-byte little-endian length at payload offset 0x28. The repaired payload MD5 matches `864ff7bd83b071a2784343d933b149be` from the container.

The repaired filesystem includes:

- `/etc/assay/SHIFT-KEY.txt`: the monitor's plant key and exact hourly HMAC specification.
- `/etc/assay/OFFICE-MAIL.txt`: McHugh's plant password `Elmmere91163#`.
- `/etc/assay/plant.shadow`: bundle and surface private-key password hashes.
- `/usr/include/assay-proto.h`: the binary assay protocol for port 7731.

The assay protocol requires a HELLO request with the CRC-32 of the current gas reading string; requests use big-endian fields. After HELLO, LIST and FETCH can retrieve the encrypted assay bundle. The bundled credential standard uses an original two-digit seam, three-digit shot number, and one of `!@#$%&`.

The personnel record gives bundle holder `bridgebottom`, seam `54`, bundle class; manager holder `drinkmere`, seam `11`, staff class. The manager password is `Drinkmere11257#`, verified independently against the host root account's SHA-512 crypt hash and the unseal tool's SHA-256 check.

## Authentic flag seals

The separate crusher root filesystem contains a decoy `root.txt`. It is not the host's root flag. The authentic artifacts are `/var/lib/assay/user.txt.sealed` and `/root/root.txt.sealed`.

The host unsealer is stripped. Disassembly reveals a `BDSEAL1` format:

- 8-byte magic `BDSEAL1\0`.
- Little-endian 32-bit ciphertext length.
- First 16 bytes of HMAC-SHA256 of the ciphertext under the seal key.
- Ciphertext.

Encryption XORs each 32-byte chunk with SHA256 of the binary 32-byte seal key followed by a little-endian 32-bit chunk counter, starting at zero.

The user seal key is SHA256 of `blackdamp-user|` plus fragment B (`bda5c910`) from the assay account. The root seal key is SHA256 of `blackdamp-seal|` plus the assembled three-fragment seed, a `|`, and Smoke's root flag:

`Null0rigin{two_figures_off_a_payroll_sheet}`

Fragment B is `bda5c910` in `/home/assay/.assay/seal-frag-B.txt`. Fragment C is `f4c01df2` in `/root/.seal-frag-C`. Fragment A is inside the encrypted assay bundle.

The unseal executable separately enforces a live boot record, manager password, SHA256 of the assembled seed, current six-digit SHA256 TOTP, and chain-key check. These gates do not add boot identity, password, or current TOTP to the ciphertext key. Offline reimplementation can therefore authenticate and recover the original flag plaintexts once the bundle fragments and Smoke flag are known. No VM was booted and no live privilege-escalation chain was exercised.

## Reproducible scripts

- `export.py`: read-only OVA artifact export using dissect.target.
- `recover_firmware.py`: restore and verify the SquashFS payload; export its files.
- `crack_bundle_hash.py`: bounded offline search over the named bundle holder's 6,000 shot/marker candidates against its firmware SHA-512 crypt hash. Successful archive extraction confirms the password. `crack_bundle.py` supplies an alternative direct encrypted-header search.
- `solve_blackdamp.py`: authenticate both sealed ciphertexts, decrypt their flags, and independently verify the manager and bundle password hashes. Writes `blackdamp-results.json`.

Run scripts from the project root with `.venv\Scripts\python.exe`. Findings were recovered from verified VM artifacts.

