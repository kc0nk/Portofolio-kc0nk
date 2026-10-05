---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Crypto"
challenge: "wavy"
flag: "tjctf{ch3bysh3v_p0lyn0m1!l_676767}"
teknik: "Keystream dari polinomial Chebyshev T_n(x) mod prima secp256k1; recurrence linier 2-suku dieksponensiasi lewat matriks"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# wavy — TJCTF 2026 (Crypto)

## Deskripsi Singkat

Enkripsinya adalah XOR dengan keystream yang diturunkan dari `T_{10^25}(0x1337C0DE)` mod prima secp256k1, di mana `T_n` adalah **polinomial Chebyshev jenis pertama**.

## Analisis & Eksploitasi

Recurrence `T_{n+1}(x) = 2x·T_n(x) − T_{n-1}(x)` adalah recurrence linier dua-suku — nyatakan sebagai matriks 2×2 dan eksponensiasi lewat squaring. `10^25` tereduksi jadi ~83 perkalian matriks.

```python
def cheb(n, x, p):
    M = [[2*x % p, -1 % p], [1, 0]]
    R = mat_pow(M, n - 1, p)               # eksponensiasi biner
    # [T_n, T_{n-1}]ᵀ = R · [x, 1]ᵀ
    return (R[0][0] * x + R[0][1]) % p
```

XOR encoding big-endian 32-byte dari `T_{10^25}` terhadap ciphertext-nya, diulang (cycling).

## Flag

```
tjctf{ch3bysh3v_p0lyn0m1!l_676767}
```
