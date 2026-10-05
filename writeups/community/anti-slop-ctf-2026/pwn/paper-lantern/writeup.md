---
ctf: "Anti-Slop CTF 2026"
kategori: "Pwn (Binary Exploitation)"
challenge: "Paper Lantern"
flag: "slopped{faulted_crt_seams_burn_open}"
teknik: "Bellcore fault attack pada RSA-FDH signer berbasis CRT; satu signature bercacat memfaktorkan modulus lewat gcd(s^e-m, n)=p"
---

# Paper Lantern — Anti-Slop CTF 2026 (Pwn)

## Deskripsi Singkat

Signer RSA-FDH berbasis CRT yang tidak memverifikasi output-nya sendiri sebelum mengembalikannya. Primitive fault di jalur COMMENT memicu fault komputasi CRT pada satu prima.

## Analisis

Kalau signer CRT menghitung `s_p = m^d mod p` dengan benar tapi `s_q` salah, signature gabungan `s` memenuhi `s^e ≡ m (mod p)` tapi tidak `(mod q)`. Jadi `s^e − m` adalah kelipatan `p` dan bukan kelipatan `q`. Karena itu `gcd(s^e − m, n) = p` — memfaktorkan modulus lewat serangan Bellcore (Boneh–DeMillo–Lipton, 1996). Dengan `(p, q)` di tangan, hitung private exponent dan forge signature valid untuk audit apa pun, termasuk capsule yang membawa opcode flag `0x7f` yang ditolak jalur `SIGN`.

**Bisakah signer ini dibypass tanpa fault Bellcore?** Apa pun yang memulihkan private key berfungsi. Serangan padding-oracle terhadap FDH tidak relevan karena FDH dengan `m mod n` tidak punya padding oracle. Faktorisasi langsung atas prima 256-bit tidak feasible secara komputasi. RSA-FDH sebaliknya sudah kokoh. Fault Bellcore adalah satu-satunya jalur praktis yang dimaksud karena implementasi CRT signer inilah yang menyediakan primitive fault-nya.

## Eksploitasi / Solusi

Picu fault via jalur COMMENT, hitung `gcd(s^e - m, n)` untuk mendapat `p`, turunkan `q = n/p`, hitung private exponent `d` dari `(p, q, e)`, forge signature valid atas capsule yang membawa opcode flag:

```
slopped{faulted_crt_seams_burn_open}
```

## Catatan / Insight

**Pelajaran untuk defender:** perbaikannya adalah sign-lalu-verify sebelum mengembalikan hasilnya — cuma menambah satu eksponensiasi modular ekstra, dan itu mengubah serangannya jadi denial-of-service alih-alih kompromi kunci penuh. Signer CRT mana pun yang tidak memverifikasi output-nya sendiri sebelum mengembalikannya berisiko terhadap kelas serangan ini — fault hardware, fault software, bahkan race condition bisa memicu fault CRT satu-prima yang sama.

## Flag

```
slopped{faulted_crt_seams_burn_open}
```
