# Bears

- **Category:** Reverse Engineering
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Steganografi sederhana pada aset PNG. Flag ditemukan sebagai data ASCII tertanam di binary image; tidak ada service remote.

## Metode
Inspect file → strings/byte search → recover embedded flag.

## Command / primitive
```bash
unzip misc_bears.zip
file misc_bears/bear.png
strings -a misc_bears/bear.png | grep -E 'brunner|flag|\{'
```

## Rumus / constraint
```text
PNG binary data ⟶ embedded ASCII ⟶ flag
```

## Solver / code snippet
```python
#!/usr/bin/env python3
from pwn import *
import re, sys

path = sys.argv[1]
data = open(path, "rb").read()
m = re.search(rb"brunner\{[^}]+\}", data)
if not m:
    log.failure("Flag tidak ditemukan")
    sys.exit(1)
log.success(f"Flag: {m.group().decode()}")
```

## Hasil
```text
brunner{b34rs_347_b337s}
```
