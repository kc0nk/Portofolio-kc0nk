---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Crypto"
challenge: "squares"
flag: "tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}"
teknik: "Titik stasioner bentuk kuadratik H(x)=xᵀMx−2cᵀx → sistem linier mod 257, diselesaikan Gaussian elimination"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# squares — TJCTF 2026 (Crypto)

## Deskripsi Singkat

`out.txt` berisi matriks `M` 52×52 dan vektor `c` 52-elemen di atas `F_{257}`, dan flag-nya adalah titik stasioner dari `H(x) = xᵀMx − 2cᵀx`.

## Analisis & Eksploitasi

Menyetel `∇H = 0` memberikan `(M + Mᵀ) x ≡ 2c (mod 257)` — satu sistem linier mod prima kecil. Gaussian elimination di `GF(257)` memulihkan `x`, yang di-decode jadi ASCII.

```python
A = [[(M[i][j] + M[j][i]) % 257 for j in range(52)] for i in range(52)]
b = [(2 * c[i]) % 257 for i in range(52)]
x = gauss_mod_p(A, b, 257)
print(bytes(x).rstrip(b" "))
```

## Flag

```
tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}
```
