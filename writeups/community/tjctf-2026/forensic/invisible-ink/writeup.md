---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Forensics"
challenge: "invisible-ink"
flag: "tjctf{p0lygl0t_f1les_4r3_50_c00l}"
teknik: "Polyglot PDF+ZIP; teks putih-di-atas-putih di PDF membawa password ZIP; distorsi swirl dibalik dengan strength negatif"
---

# invisible-ink — TJCTF 2026 (Forensics)

## Deskripsi Singkat

Sebuah polyglot: file-nya adalah PDF valid (terbaca dari `%PDF-` di atas) **dan** ZIP valid (terbaca dari EOCD di bawah).

## Analisis & Eksploitasi

Halaman 2 dari PDF-nya punya teks putih-di-atas-putih yang tetap diekstrak PyMuPDF dari layer teks — itulah password ZIP-nya: `DBf8nEBgwRhZ`. Di dalam ZIP terenkripsi: `original_distorted.png`, sebuah flag tulisan tangan yang terdistorsi swirl. Pakai `skimage.transform.swirl(img, center=(w/2, h/2), strength=-8.5, radius=540)` — strength **negatif**-nya membalik distorsi aslinya.

## Flag

```
tjctf{p0lygl0t_f1les_4r3_50_c00l}
```
