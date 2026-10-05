---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "Coupon Stacking"
flag: "bitflag{c0up0n_st4ck1ng_1s_4_d34l}"
teknik: "Prop server React (couponFlag) sudah ada di payload RSC sebelum JS apa pun berjalan; bug logika coupon-stacking hanyalah umpan"
sumber: "https://github.com/Abdelkad3r/RIFFHACK/tree/main/04-web4-coupon-stacking"
---

# Coupon Stacking — RIFFHACK 2026 (Web)

## Deskripsi Singkat

Dua bug bertumpuk di halaman listing yang sama. Bug "yang dimaksud" adalah kesalahan hitung dedup coupon sisi-client yang menumpuk diskon sampai totalnya nol. Shortcut sebenarnya: rahasia win-state-nya adalah prop server-component React, dan Next.js sudah men-serialize-nya ke HTML SSR sebelum UI coupon apa pun mount.

## Analisis

Bug "yang dimaksud": normalisasi (`trim().toUpperCase()`) dipakai untuk pengecekan *nilai* tapi bukan pengecekan *dedup*. Jadi `WELCOME20`, `welcome20`, `Welcome20`, ` WELCOME20`, dan `WELCOME20 ` semuanya lolos kedua gerbang, masing-masing menyumbang 20%. Lima entri → 100% off → dialog me-render prop `couponFlag`.

## Eksploitasi / Solusi

Ambil shortcut-nya — prop flag-nya sudah ada di HTML sebelum JavaScript apa pun berjalan:

```bash
$ curl -s http://159.89.230.27/listing/macro-builder \
     | grep -oE '"couponFlag":"[^"]+"'
"couponFlag":"bitflag{c0up0n_st4ck1ng_1s_4_d34l}"
```

Tanpa login, tanpa cookie, tanpa interaksi UI.

## Catatan / Insight

Kedua bug-nya secara konseptual terpisah: kesalahan hitung coupon-stacking adalah bug logika di client, dan kebocoran prop-nya adalah bug bentuk-framework karena server component menyerahkan prop-nya ke client component dengan menuliskannya ke HTML.

## Flag

```
bitflag{c0up0n_st4ck1ng_1s_4_d34l}
```
