---
ctf: "DalCTF 2026"
kategori: "Crypto"
challenge: "Fun with RSA"
flag: "dalctf{s3gf4u17_r54_m1x3d_w17h_x0r}"
teknik: "Script mempublikasikan signature RSA s = m^d mod n, jadi m = pow(s, e, n) memulihkan pesan dalam dua baris; jalur Bellcore fault juga berhasil sebagai alternatif"
---

# Fun with RSA — DalCTF 2026 (Crypto)

## Deskripsi Singkat

Script mempublikasikan nilai RSA 512-bit dengan beberapa lapis pengalih perhatian:

- `ct = c XOR p XOR q` — "ciphertext" di-blind dengan XOR terhadap kedua prima, jadi `ct` saja tidak berguna.
- `s = pow(m, d, n)` — **signature RSA** dari pesan plaintext. Dipublikasikan.
- `spz` — half-signature bergaya CRT dengan fault yang disengaja di sisi `p`: `sp ⊕ 1` disuntikkan sebelum `crt_combine(sp_faulty, sq)`.

Nama challenge-nya mengisyaratkan *ketiga* trik (`segfault` = fault-nya, `RSA mixed with XOR` = blinding `ct`). Jalur yang dimaksud adalah **serangan Bellcore**.

## Eksploitasi / Solusi — Jalur Trivial: `pow(s, e, n)`

`s = m^d mod n` adalah *signature RSA dari pesan*, dan eksponen publik `e` diberikan. Jadi:

```python
m = pow(s, e, n)
print(long_to_bytes(m))
```

Tanpa faktorisasi, tanpa XOR, tanpa analisis fault. Script-nya menyerahkan pesannya langsung.

→ `dalctf{s3gf4u17_r54_m1x3d_w17h_x0r}`

## Jalur Fault Bellcore — Juga Berhasil

Demi kelengkapan — dan karena challenge ini jelas menginginkan ini — signature CRT ber-fault memberi **serangan Bellcore** buku-teks:

`spz ≡ sp_faulty (mod p)` tapi `≡ sq (mod q)`. Maka:

- `s ≡ spz (mod q)` (setengah-q tidak terpengaruh fault sisi-p)
- `s ≢ spz (mod p)`

Karena itu `s − spz` adalah kelipatan `q` tapi bukan `p`:

```python
from math import gcd
q = gcd(s - spz, n)
p = n // q
phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)
c   = ct ^ p ^ q                # batalkan blinding XOR
m   = pow(c, d, n)
print(long_to_bytes(m))
```

Kedua jalur memulihkan flag yang sama.

## Catatan / Insight

**Pelajaran untuk defender:** kalau challenge RSA CTF mempublikasikan `s = m^d mod n`, **coba `pow(s, e, n)` sebelum apa pun.** Di produksi, bug setaranya adalah mempublikasikan signature bersama public key lalu menganggap pasangan itu "pesannya tersembunyi karena sudah dienkripsi." Signature adalah permutasi dari pesan di bawah private key; public key membalikkannya.

Jalur fault Bellcore adalah serangan terkenal 1997 terhadap RSA berbasis CRT (Boneh, DeMillo, Lipton): satu fault komputasi di setengah-p penandatanganan CRT membocorkan `gcd(s - s_faulty, n) = q`. Implementasi CRT-RSA produksi bertahan dengan **memverifikasi setiap signature terhadap public key sebelum mengembalikannya** — kalau `pow(sig, e, n) != message`, batalkan operasi penandatanganan. Ini salah satu pertahanan fault-attack termurah dan wajib di PKCS#1 v2.2.

**Kelas bug:** signature RSA dipublikasikan seolah-olah ciphertext; serangan fault CRT sebagai fallback kanonik.

## Flag

```
dalctf{s3gf4u17_r54_m1x3d_w17h_x0r}
```
