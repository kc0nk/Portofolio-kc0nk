---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Web"
challenge: "Treasure Hunt"
flag: "tjctf{s1lv3r_and_g0ld}"
teknik: "Triad recon klasik: view-source, POST → cookie, /robots.txt"
---

# Treasure Hunt — TJCTF 2026 (Web)

## Deskripsi Singkat

Tiga segmen flag tersembunyi di bagian berbeda dari halaman yang sama.

## Analisis & Eksploitasi

Jalur yang dimaksud adalah triad recon klasik: **view source** (ada `<p>` yang disembunyikan CSS berisi `_and_`), **POST ke form** (menyetel cookie `silver_coffer` berisi `s1lv3r`), dan **`/robots.txt`** (men-`Disallow` `/gold-coffer`, tempat segmen ketiga hidup). Gabungkan `s1lv3r` + `_and_` + `g0ld`.

```bash
curl -sc /tmp/c -X POST https://treasure-hunt.tjc.tf/ && grep silver_coffer /tmp/c
curl -s https://treasure-hunt.tjc.tf/robots.txt
curl -s https://treasure-hunt.tjc.tf/gold-coffer
```

## Flag

```
tjctf{s1lv3r_and_g0ld}
```
