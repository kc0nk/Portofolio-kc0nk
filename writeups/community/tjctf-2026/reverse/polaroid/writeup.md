---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Reverse"
challenge: "polaroid"
flag: "tjctf{develop_the_picture}"
teknik: "Password tertanam di Mach-O ARM64 + XOR blob const dengan password sebagai keystream berulang → PNG tercermin horizontal"
---

# polaroid — TJCTF 2026 (Reverse)

## Deskripsi Singkat

Binary Mach-O ARM64 macOS yang meminta password, mendekripsi blob tertanam dari `__TEXT.__const` dengan XOR, lalu menulis PNG yang dicerminkan horizontal ke disk.

## Analisis

Dua bagian yang perlu dipulihkan:

1. **Password-nya** — `exposeTheNegative` — duduk sebagai perbandingan immediate byte-demi-byte di fungsi pengecekan password. Terlihat langsung di output `otool -tV`.
2. **Rutin XOR-nya** — index modulo `len(password)` (= 17), meng-XOR setiap byte dari blob const 6324-byte dengan `password[i % 17]`.

## Eksploitasi / Solusi

```python
out = bytes(b ^ password[i % 17] for i, b in enumerate(const_data))
open("flag.png", "wb").write(out)
```

Buka PNG-nya, cerminkan horizontal (binary ini sengaja menghasilkan bayangan cermin), baca flag-nya.

## Flag

```
tjctf{develop_the_picture}
```
