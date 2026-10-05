---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Pancake Stack"
flag: "ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}"
teknik: "Seed 32-bit AES-256 key + hint SHA256(seed) brute-force; collision truncated AES_k1(y||0) memaksa dua nonce berbeda memakai (ek,iv) sama → reuse keystream AES-GCM"
---

# Pancake Stack — ASIS CTF Quals 2026 (Crypto, Medium)

## Deskripsi Singkat

"Fluffy KDF"-nya bermuara pada reuse keystream AES-GCM, dibuka lewat dua bug yang bisa digabung.

## Analisis — Konstruksinya

`challenge.json` mempublikasikan `d=32`, hint `a`, nonce `n=[n1,n2]`, `h` (AAD), `m` (128 byte nol plaintext dikenal), `y` (blob AEAD flag), dan `z` (tiket tersegel).

**Bug 1 — hint seed 32-bit.** `k1` adalah kunci AES-256 penuh yang dibangkitkan dari `seed` 32-bit saja, dan `hint = SHA256("K1-SEED-HINT" || be32(seed))` adalah oracle langsung untuknya. Iterasi `seed ∈ [0, 2^32)`, hash, bandingkan — brute-forcer C threaded menemukan `seed = 0x22c4d3ef` dalam hitungan detik, memberi `k1`.

**Bug 2 — collision truncated memaksa satu keystream.** `find_collision(k1, n2)` mencari `alt ≠ n2` dengan 96 bit teratas yang sama dari `AES_k1(alt||0)`. Setelah `alt` ditemukan, generation menghasilkan `sample = encrypt_authenticated(k1, k2, n1, alt, ad, PLAINTEXT_NOL)` dan `y = encrypt_authenticated(k1, k2, n1, n2, ad, flag)`. Menelusuri `diffuse_state` untuk keduanya: `j`, `w1`, `w2`, `r1`, `r2` semuanya **identik** (karena `j` identik by construction dan `n1` sama), jadi `derive_keys(k2, n1, state)` mengembalikan `(ek, iv, ck)` yang **sama** untuk keduanya — tanpa peduli `k2` rahasia. AES-GCM adalah mode CTR, jadi `(key, nonce)` identik berarti keystream identik. Plaintext sample-nya nol, jadi `sample.ciphertext = keystream`:

```
flag = y.ciphertext XOR sample.ciphertext[:len(flag)]
```

**Memulihkan ciphertext sample.** Ciphertext sample hanya hidup di dalam tiket tersegel `z`. Hitung ulang `alt` dengan scan `2^32` yang sama (diperluas untuk enumerasi setiap collision), coba masing-masing, biarkan tag GCM memilih yang benar. Tiket itu lalu terdekripsi memberi keystream yang dipakai ulang.

## Eksploitasi / Solusi

```
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

## Catatan / Insight

**Kunci 256-bit yang di-seed dari 32 bit cuma punya keamanan 32 bit** — dan mempublikasikan fungsi deterministik apa pun dari seed itu (si "hint") membocorkannya langsung. **Memotong PRP menciptakan collision by design**: membuang 32 bit mengubah AES jadi map 96-ke-96 dengan collision yang sering; di sini satu collision memaksa dua nonce berbeda menurunkan `(ek, iv)` yang sama. **Reuse nonce/keystream fatal untuk GCM (dan mode-CTR apa pun)** — salah satu dari dua pesan yang bertabrakan diketahui nol-semua, jadi ciphertext-nya adalah keystream mentah, dan XOR mengungkap yang lain.

## Flag

```
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```
