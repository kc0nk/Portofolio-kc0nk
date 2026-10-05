---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Crypto"
challenge: "TAUtology"
flag: "tjctf{w0rth_th3_w41t_6283185_zzz}"
teknik: "ReDoS catastrophic backtracking dipakai sebagai side-channel maju (binary-search oracle atas timeout)"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# TAUtology — TJCTF 2026 (Crypto)

## Deskripsi Singkat

Oracle pencocokan regex atas flag: timeout 0.20 detik per query, 1200 query total, tanpa pengungkapan hasil — hanya keluaran biner "ok"/"timeout".

## Analisis & Eksploitasi

Timeout-nya **adalah** side channel-nya. Bangun **pola ReDoS** dengan zero-width lookahead anchor:

```
^(?=<prefix_diketahui><charset>)(.+)+ZQXJ
```

Kalau `<prefix_diketahui><charset>` cocok dengan prefix flag, lookahead-nya berhasil, cursor tetap di posisi 0, dan `(.+)+` mengalami catastrophic backtracking terhadap seluruh string flag sampai menyerah di sufiks `ZQXJ` yang mustahil — 200 ms. Kalau prefix-nya tidak cocok, lookahead langsung gagal di posisi 0 dan regex-nya kembali dalam mikrodetik. **Binary-search charset**-nya dengan membagi dua di setiap probe; sampling min-of-4 dan baseline berjalan dari regex kontrol menyerap jitter jaringan.

## Flag

```
tjctf{w0rth_th3_w41t_6283185_zzz}
```
