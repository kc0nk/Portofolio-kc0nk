# Smoke solution

Recovered flags:

- User: `Null0rigin{the_wordlist_was_the_target_all_along}`
- Root: `Null0rigin{two_figures_off_a_payroll_sheet}`

Recovered plant passwords (both independently verified against the VM's SHA-512 crypt hashes):

- assay: `sk-sidebourne96493#`
- root: `Hallden48371#`

## Method and verification

The supplied repository ZIP contained metadata only. Smoke was retrieved from the `boot2root-v1` release's `NullOrigin_Boot2Root_Chain.7z`. The extracted OVA's SHA-256 matches its bundled manifest:

`8d8608897621e72b53bfe588eca067c04de9ddfb030ee8462dac7696353e4be3`

The OVA filesystem was read with `dissect.target`. No original guest files were modified, and no VM was booted.

The shift-board records at `/var/lib/smokeboard/pit-records.tar.gz` contain the credential standard and personnel extract. The standard uses a site vocabulary token, an account-class transform, the holder's original two-digit seam, a three-digit shot, and one marker from `!@#$%&`. The personnel extract gives assay holder `sidebourne`, seam `96`, class `bundle`; root holder `hallden`, seam `48`, class `staff`. Testing the named holder tokens and 6,000 shot/marker combinations per account recovered the passwords. This succeeds without exhaustively searching the full site vocabulary.

The assay log is a sequence of 32-byte little-endian records with layout `<IIf8s12s`. Its sole reading above 20 is entry 1009, reading approximately 21.44, whose instrument tag is `93563208e2ee`. `/home/clerk/office.notes` supplies the second fragment, `602f63e441f2`.

The unsealing binaries contain symbols and can be disassembled. Their seal format is:

- bytes 0..7: `SMKSEAL1`
- bytes 8..11: the first four bytes of SHA-256 of the plaintext
- bytes 12..13: plaintext length, little-endian unsigned 16-bit
- bytes 14 onward: plaintext XOR a derived stream

For a key phrase, let `key = SHA256(phrase).hexdigest()`. Stream block `i` is `SHA256((key + ':' + decimal(i)).encode()).digest()`, starting at zero.

The user phrase is `assay:<password>`. The root phrase is `<fault-code>:<office-code>:<root-password>`. Both recovered flag plaintexts match the stored four-byte SHA-256 check. The recovered passwords also match the actual account hashes, providing an independent check.

The root `unseal` program checks effective root privileges and compares `/run/smokeboard.boot` with the kernel boot ID before opening the root docket. This is a program-level gate: the boot ID does not enter the root seal's encryption key. Reimplementing the cipher therefore recovers the authentic root flag offline. The separate `.boot-notice` is a fallback message and is not reported as the root flag.

## Intended live path (identified statically; not exercised)

The shift board listens on TCP 7701 and challenges each connection with a nonce. Its opening figure is the first eight hex characters of SHA-256 of the nonce, without a newline. The certificate depot on 7702 is a chrooted decoy.

SSH permits password login for assay into the restricted `/usr/local/bin/pitsh`. The shell permits the report language `awk`, a likely route to a system shell. The assay log provides the fault fragment. Clerk's minute job opens `/var/lib/assay/spool` with mode 0733 for four seconds, closes it, and executes `*.tally` as clerk. Winning that window grants clerk execution. Clerk can read the office fragment and execute root-owned SUID `lampcheck`.

`lampcheck` removes only the first `../` occurrence. A certificate name beginning with an expendable traversal, such as `../../../../etc/shadow`, becomes `../../../etc/shadow` relative to `/var/lib/lamps`, permitting a read of the host's shadow file. The root password follows the same site standard. After becoming root, the intended final command is:

```sh
/usr/local/bin/unseal 93563208e2ee 602f63e441f2
```

Supply `Hallden48371#` at its password prompt. The live race and shell escape have not been tested here; the flags themselves were recovered and validated from the VM artifacts.

## Reproduce

Run from the project root:

```powershell
.venv\Scripts\python.exe ctf-smoke\solve_smoke.py
```

The script uses the exported guest artifacts under `ctf-smoke/guest` and writes `ctf-smoke/smoke-results.json`.
