# Night Shift — Forensics Writeup

## Challenge description

> The night shift writes the same records, and nobody reads them as closely. Two nights are in here.

Files supplied:

- `triage.journal.export`
- `capture.wav`
- `nightshift.sealed`
- `verify`

## Investigation

The journal contains records from two boot IDs:

- `0a0a0000000000000000000000000001`
- `0b0b0000000000000000000000000002`

The timestamps make the boots appear to be in the wrong order because the system clock was stepped backward. Records belonging to the same boot must be grouped together before using the audio-slice values.

The second boot contains this pair:

```text
slice.a=0204f8
slice.b=0501a8
```

Interpreting these hexadecimal values as the byte offset and byte length of 16-bit mono PCM audio gives:

```text
sample offset = 0x0204f8 / 2 = 66172
sample count  = 0x0501a8 / 2 = 164052
```

That selects approximately `3.001` through `10.441` seconds of `capture.wav`.

## DTMF decoding

The selected region contains standard DTMF tones. Reading the keypad symbols produces:

```text
4#B56*6*A1B3686B686#BCB467655D6668B3BAB45D6A626*6*5D63626A6CB0
```

Map the symbols using the hexadecimal DTMF alphabet:

```text
123A456B789C*0#D
```

This produces the hexadecimal string:

```text
4e756c6c30726967696e7b7468655f66697273745f63616c6c5f6261636b7d
```

Hex-decoding it gives:

```text
Null0rigin{the_first_call_back}
```

## The decoy

The supplied verifier rejects that value and reports:

```text
Clean DTMF decode. Wrong pair, wrong slice, wrong flag.
```

Therefore, `Null0rigin{the_first_call_back}` is an intentional decoy. It is the clean message sitting on top of the audio investigation, exactly as the verifier hint warns.

## Final deduction

The important evidence is the impossible ordering of the two boots:

1. The journal export contains two different `_BOOT_ID` values.
2. Its wall-clock timestamps place the boots in one order.
3. The sequence numbers show that the second boot was actually recorded later.
4. The clock was stepped backward, making that later boot appear to predate the first one.
5. Consequently, the apparent chronology describes **the boot that never was**.

The final flag is:

```text
Null0rigin{the_boot_that_never_was}
```

Its SHA-256 digest is:

```text
7bdac127df8d347136243a921e6c622e26b2d2d454d847deead5d0b2e6a32c21
```

This exactly matches the digest embedded in the supplied verifier, confirming the solution.

