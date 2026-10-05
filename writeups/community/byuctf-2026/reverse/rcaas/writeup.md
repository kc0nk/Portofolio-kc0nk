---
ctf: "BYUCTF 2026"
kategori: "Reverse Engineering"
challenge: "RCaaS"
flag: "byuctf{s3rv1c3s_c4n_b3_r3v3rs3_3ng1n33r3d_t00}"
teknik: "Servis SUID Go; 30 persamaan multiplikatif mod-256 + 9 posisi tetap"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# RCaaS — BYUCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Handout-nya adalah binary Go x86-64 yang menginstal dirinya sendiri sebagai `kardianos/service`. Saat dijalankan, ia membaca `/opt/atyourservice/flag.txt` dan menerima flag jika dan hanya jika:

1. Diawali `byuctf{`, panjang persis `0x2E = 46` byte.
2. Sembilan posisi spesifik sama dengan `'3'` (`0x33`).
3. Tiga puluh persamaan berbentuk `(flag[i] · flag[j]) & 0xff == C` dipenuhi.
4. `flag[33] >= 0x60` dan `flag[35] >= 0x60`.

## Analisis

Setiap persamaan menetapkan satu byte dari satu byte yang diketahui dan satu yang belum. Tetapkan prefix `byuctf{`, sufiks `}`, dan sembilan posisi tetap; lalu iterasi lewat 30 persamaan, menyelesaikan masing-masing begitu ia menjadi brute satu-unknown atas ASCII printable. Satu byte ambigu di posisi 20 — pilih yang membuat `_b3_` terbaca sebagai leetspeak Inggris yang masuk akal.

## Eksploitasi / Solusi

```
byuctf{s3rv1c3s_c4n_b3_r3v3rs3_3ng1n33r3d_t00}
```

## Catatan / Insight

**Pelajaran untuk defender:** flag-nya adalah pelajarannya sendiri. *"Services can be reverse-engineered too"* (layanan juga bisa direverse-engineer) — berjalan sebagai system service tidak membeli anti-RE. Verifier-nya tetap harus meng-encode pengecekannya di suatu tempat.

## Flag

```
byuctf{s3rv1c3s_c4n_b3_r3v3rs3_3ng1n33r3d_t00}
```
