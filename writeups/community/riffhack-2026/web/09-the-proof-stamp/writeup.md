---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "The Proof Stamp"
flag: "bitflag{md5_1s_br0k3n_l1k3_my_h34rt}"
teknik: "\"Integrity check\" cuma MD5 dari nama file itu sendiri; server men-stamp konstanta flag ke fileHash tiap submission diterima"
---

# The Proof Stamp — RIFFHACK 2026 (Web)

## Deskripsi Singkat

`POST /api/reviews` menerima nama file dari body request dan memvalidasinya terhadap allow-list tiga-entri dengan referensi MD5 hardcoded. Tidak ada file yang diupload; tidak ada byte yang di-hash. Setiap submission yang diterima, server men-stamp string konstan ke kolom `fileHash` di baris itu. Konstanta itulah flag-nya.

## Analisis

Bundle client-nya punya tiga nama file allow-listed dengan "referensi MD5"-nya masing-masing. Submission body-nya JSON biasa, bukan `multipart/form-data`. "Pengecekan hash"-nya secara harfiah MD5 dari *string nama file*, yang trivial benar untuk salah satu dari tiga nama allow-listed.

## Eksploitasi / Solusi

```bash
curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"reviewText":"works great","filename":"exploitation_proof.png","listingId":"macro-builder"}' \
  http://<host>/api/reviews \
  | grep -oE 'bitflag\{[^}]+\}'
# bitflag{md5_1s_br0k3n_l1k3_my_h34rt}
```

`fileHash` di respons adalah konstanta yang di-stamp. Tidak ada file diupload, tidak ada byte di-hash, tidak ada bukti diperiksa. "Pengecekan"-nya terpenuhi hanya dengan menamai file salah satu dari tiga string.

**Fallback SQLi:** kalau POST-nya 500, `UNION SELECT fileHash FROM Review` pada baris buatan user mana pun menunjukkan flag ter-stamp yang sama. Setiap baris review "terverifikasi" punya nilai `fileHash` yang sama — field-nya adalah kebohongan yang tertanam di skema.

## Catatan / Insight

Tiga kegagalan berlapis bersama-sama mengeja payload flag-nya (mempercayai nama file untuk integritas, memakai MD5 untuk primitive referensi, dan menulis konstanta ke kolom yang berpura-pura dihitung): `md5_1s_br0k3n_l1k3_my_h34rt`.

## Flag

```
bitflag{md5_1s_br0k3n_l1k3_my_h34rt}
```
