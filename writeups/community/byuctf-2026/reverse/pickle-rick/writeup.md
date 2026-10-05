---
ctf: "BYUCTF 2026"
kategori: "Reverse Engineering"
challenge: "Pickle Rick"
flag: "byuctf{1m_p1ckl3_r1111ck!}"
teknik: "Token rick/pickle → bit → byte di-XOR 0x67 → ELF yang .rodata-nya membawa flag"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# Pickle Rick — BYUCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Handout-nya adalah 68.032 token `rick` dan `pickle`, persis `8504 × 8`.

## Analisis

Perlakukan `rick = 0`, `pickle = 1`, MSB-first, kemas 8 bit per byte. Byte pertama ter-decode jadi `0x18` — bukan magic ELF. Tapi `0x18 ⊕ 0x7F = 0x67`, dan XOR yang sama berlaku untuk setiap byte:

```python
toks = open("pickled.txt").read().split()
bits = [0 if t == "rick" else 1 for t in toks]
buf  = bytearray()
for i in range(0, len(bits), 8):
    b = 0
    for k in range(8):
        b = (b << 1) | bits[i + k]
    buf.append(b ^ 0x67)
open("pickled.elf", "wb").write(buf)
```

## Eksploitasi / Solusi

```bash
$ file pickled.elf
pickled.elf: ELF 64-bit LSB executable, statically linked, stripped
$ strings -n 6 pickled.elf | head -1
byuctf{1m_p1ckl3_r1111ck!}
```

## Catatan / Insight

**Pelajaran untuk defender:** obfuskasi binary apa pun yang meng-XOR dengan satu byte hanya berjarak *satu pengecekan entropi* dari ter-un-obfuskasi. Byte `0x67` yang berulang (padding-nol yang ter-encode) membocorkan kuncinya.

## Flag

```
byuctf{1m_p1ckl3_r1111ck!}
```
