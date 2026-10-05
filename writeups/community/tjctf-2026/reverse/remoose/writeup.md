---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Reverse"
challenge: "remoose"
flag: "tjctf{5ma11_m00s3}"
teknik: "ELF terkorupsi (0x00→0x20 + byte magic ke-4 diubah); setelah diperbaiki, fungsi berantai flag()→flag4() mencetak flag lewat putchar immediate"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# remoose — TJCTF 2026 (Reverse)

## Deskripsi Singkat

ELF-nya terkorupsi dengan dua cara spesifik: **setiap byte 0x00 diganti dengan 0x20** (spasi), dan **byte ke-4 magic ELF** diubah dari `0x46` (`F`) jadi `0x4b` (`K`). `file` melaporkannya sebagai "data".

## Eksploitasi

Balikkan kedua korupsi tersebut:

```python
data = open("remoose", "rb").read()
fixed = bytearray(b if b != 0x20 else 0x00 for b in data)
fixed[3] = 0x46
open("remoose-fixed", "wb").write(fixed)
```

Begitu ELF-nya valid, binary-nya tidak di-strip — lima fungsi berantai `flag()` → `flag1()` → … → `flag4()` masing-masing meng-`putchar()` satu immediate dan tail-call ke fungsi berikutnya. Flag-nya duduk di hasil disassembly sebagai rangkaian baris `mov edi, 't'; call putchar; mov edi, 'j'; …`.

## Flag

```
tjctf{5ma11_m00s3}
```
