---
ctf: "DalCTF 2026"
kategori: "Crypto"
challenge: "Angry Shamir"
flag: "dalctf{sm4ll_f4ct0rs_4r3_d4ng3r0us_1n_rs4}"
teknik: "Modulus RSA 2054-bit dengan faktor prima kecil (67); n % 67 == 0, dekripsi dengan phi = 66 * (q-1)"
---

# Angry Shamir — DalCTF 2026 (Crypto)

## Deskripsi Singkat

Handout mempublikasikan `n` (2054 bit), `e = 65537`, dan `c`. Nama challenge-nya adalah seluruh petunjuk: "Shamir" adalah **S** dalam RSA, "Angry" = ada yang salah dengan modulusnya.

## Analisis

`n` terlihat seperti modulus RSA 2054-bit sungguhan, tapi trial division dengan beberapa prima kecil pertama langsung memberi:

```python
>>> n % 67
0
```

Generator prima gagal menolak faktor kecil. `n = 67 · q` di mana `q` lolos Miller-Rabin.

## Eksploitasi / Solusi

Dekripsi dengan `phi` yang benar:

```python
from Crypto.Util.number import long_to_bytes

p = 67
q = n // 67
phi = (p - 1) * (q - 1)        # 66 * (q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

→ `dalctf{sm4ll_f4ct0rs_4r3_d4ng3r0us_1n_rs4}`

## Catatan / Insight

**Pelajaran untuk defender:** generator prima RSA mana pun harus menolak kandidat dengan faktor kecil saat sampling. Pengecekan sederhana `for small_p in PRIMES[:1000]: if cand % small_p == 0: continue` berjalan dalam mikrodetik dan menangkap bug ini. Library RSA produksi (`BN_generate_prime_ex` milik OpenSSL, dsb.) melakukan persis ini; membuat sampler prima sendiri yang digerakkan RNG tanpa penolakan faktor kecil adalah kelas bug-nya.

Untuk challenge RSA CTF apa pun yang judulnya mengisyaratkan "small", "tiny", "weak", "broken", atau "angry", **lakukan trial division dulu** sebelum meraih Fermat, Wiener, common-factor, atau Coppersmith. Pengecekan dua baris menyingkirkan kesalahan paling malas.

**Kelas bug:** generator prima rusak; modulus RSA berfaktor kecil.

## Flag

```
dalctf{sm4ll_f4ct0rs_4r3_d4ng3r0us_1n_rs4}
```
