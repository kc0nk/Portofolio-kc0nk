---
ctf: "Anti-Slop CTF 2026"
kategori: "Reverse Engineering"
challenge: "Audit Spiral"
flag: "slopped{quadratic_capsules_unlock_the_attestor}"
teknik: "Nonce ECDSA berbentuk polinomial kuadratik dalam index signing (k_i = c0+c1·i+c2·i²); dipulihkan sebagai sistem linier 4×4 mod group order dengan 4 signature"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/reverse"
---

# Audit Spiral — Anti-Slop CTF 2026 (Reverse Engineering, 500 poin)

## Deskripsi Singkat

VM penandatanganan secp256k1 membangkitkan nonce ECDSA sebagai polinomial kuadratik dalam index signing: `k_i = c0 + c1·i + c2·i²`. Dipulihkan dengan menyelesaikan sistem linier 4×4 mod group order memakai empat signature.

## Analisis

Nonce `k` milik servis ini bukan acak dan bukan deterministik-per-pesan. Ia mengikuti polinomial dalam index signing: `k_i = c0 + c1·i + c2·i²` untuk koefisien `c0, c1, c2` yang tidak diketahui. Dengan empat atau lebih signature atas digest yang sama, relasi ECDSA `s_i · k_i ≡ z + r_i · d (mod n)` menjadi sistem linier dalam unknown `(d, c0, c1, c2)` atas group order secp256k1. Menyelesaikan sistem ini memulihkan private key statis.

**Kenapa trik sistem linier berhasil untuk nonce kuadratik?** Relasi ECDSA linier dalam `(k, d)` per signature. Kalau `k_i` sendiri adalah kombinasi linier dari koefisien tidak diketahui `(c0, c1, c2)` dengan bobot per-sampel yang **diketahui** `(1, i, i²)`, maka seluruh persamaan `s_i · (c0 + c1·i + c2·i²) ≡ z + r_i·d (mod n)` linier dalam `(d, c0, c1, c2)`. Empat sampel memberi sistem 4×4 atas group order secp256k1, diselesaikan dengan eliminasi Gauss. Trik yang sama berlaku untuk nonce polinomial derajat `k` mana pun dengan `k+2` sampel.

**Mendapatkan digest stabil untuk ditandatangani.** Command signing meng-hash apa pun yang di-emit capsule yang dimuat dan menandatangani hash itu. Kalau output capsule bervariasi antar panggilan, digest-nya bervariasi dan kamu tidak bisa mengisolasi struktur nonce-nya. Muat capsule yang meng-emit persis 16 byte yang sama setiap kali (enam belas byte nol adalah versi paling sederhana), dan sekarang `z` konstan di seluruh signature. Apa pun yang bervariasi antar signature adalah struktur nonce.

## Eksploitasi / Solusi

Kumpulkan minimal empat signature dengan digest tetap, susun sistem linier 4×4 mod `n`, selesaikan untuk `(d, c0, c1, c2)`, verifikasi `d` dengan public key, lalu gunakan `d` untuk menandatangani auth challenge:

```
slopped{quadratic_capsules_unlock_the_attestor}
```

## Catatan / Insight

**Pelajaran untuk defender:** turunan nonce ECDSA yang benar seharusnya berada di standard library, bukan di kodemu sendiri. Nonce kuadratik milik Audit Spiral persis bug yang RFC 6979 (2013) tulis untuk membuatnya mustahil. Implementasi ECDSA mana pun yang memanggil `random()` atau menurunkan `k` dari `(counter, message)` alih-alih `HMAC_DRBG(private_key, message)` berisiko terhadap keluarga serangan yang sama. Checklist review konkret: grep untuk `ecdsa.sign`, `secp256k1.sign`, atau `Signature::sign` dan telusuri parameter `k`-nya kembali ke sumbernya. Kalau sumbernya bukan RFC 6979 atau `crypto/rand` yang dicampur ke HMAC-DRBG, itu temuan.

Nonce bias bukan satu kelas bug tunggal. Serangan buku-teks (`k` dipakai ulang, `k` dengan prefix/suffix tetap, `k` linier dalam `i`) sudah dikenal luas. Bias polinomial adalah bentuk yang sama satu derajat lebih tinggi. Di mana pun kamu mengontrol index dan digest pesan, kamu bisa mengangkat struktur polinomialnya jadi sistem linier.

## Flag

```
slopped{quadratic_capsules_unlock_the_attestor}
```
