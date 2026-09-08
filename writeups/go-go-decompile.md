# Go Go Decompile

- **Category:** Reverse Engineering
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Program Go memvalidasi input terhadap string hardcoded yang di-Base64 decode. Fokus utama adalah dekompilasi dan ekstraksi konstanta.

## Metode
Locate Base64 constant → Decode → compare with user input.

## Command / primitive
```text
encoding/base64.Decode
bufio.NewScanner
runtime.memequal
remote()/sendline()/recvall()
```

## Rumus / constraint
```text
input == Base64Decode(hardcoded_string)
```

## Solver / code snippet
```python
import base64
expected = base64.b64decode(HARDCODED)
assert candidate == expected
```

## Hasil
```text
brunner{g0_d3c0mp1l3d_g0_brr}
```
