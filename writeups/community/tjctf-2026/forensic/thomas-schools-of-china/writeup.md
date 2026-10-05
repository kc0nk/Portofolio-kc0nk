---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Forensics"
challenge: "thomas-schools-of-china"
flag: "tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}"
teknik: "Container kustom .tsc; flag ada di pixel dengan channel RGB yang menyimpang (bukan pixel abu-abu tubuh bebek)"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# thomas-schools-of-china — TJCTF 2026 (Forensics)

## Deskripsi Singkat

Container `.tsc` kustom: magic 4-byte, version 4-byte, width 4-byte, height 2-byte, spek format 3-byte, lalu data pixel RGBA. Render-nya menampilkan bebek pastel-hijau 60×61.

## Analisis & Eksploitasi

Flag-nya hidup di **bintik-bintik berwarna** — pixel di mana channel RGB-nya berbeda ≥5. Untuk setiap pixel semacam itu, R/G/B masing-masing di-decode jadi karakter ASCII yang bisa dicetak (jadi satu pixel = 3 byte flag). Filter pixel tubuh abu-abu (di mana `max(R,G,B) − min(R,G,B) < 5`) dan gabungkan sisanya.

## Flag

```
tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}
```
