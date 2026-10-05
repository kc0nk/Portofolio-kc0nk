---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Crypto"
challenge: "minervas-stopwatch"
flag: "tjctf{m1n3rv4_h34rd_th3_n0nc3_tick}"
teknik: "Kebocoran timing ECDSA P-256 (Minerva, CVE-2019-15809) — leading zero bit nonce terlewat; HNP lattice + LLL"
---

# minervas-stopwatch — TJCTF 2026 (Crypto)

## Deskripsi Singkat

Servis ECDSA P-256 yang implementasi scalar-mult-nya **melewati (skip) leading zero bit** dari nonce-nya. Setiap tanda tangan datang dengan waktu eksekusi server-side dalam nanosecond.

## Analisis & Eksploitasi

Urutkan tanda tangan berdasarkan waktu eksekusi; beberapa yang tercepat dihasilkan oleh nonce dengan bit tinggi yang bias — yaitu `k < 2^200`. Ini setup klasik Minerva (CVE-2019-15809): masukkan 5 tanda tangan bias semacam itu ke lattice **Hidden Number Problem** Boneh-Venkatesan, reduksi LLL, baca private key dari shortest vector-nya. Verifikasi dengan `d·G == Q`. Lalu turunkan keystream `SHA-256(d_bytes || i.to_bytes(4, "big"))` untuk `i = 0, 1, …` dan XOR ciphertext-nya.

Seluruh rantai timing-ke-key hanya butuh hitungan detik; bagian sulitnya adalah mengenali kebocoran leading-zero dari distribusi waktu eksekusi.

## Flag

```
tjctf{m1n3rv4_h34rd_th3_n0nc3_tick}
```
