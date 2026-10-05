---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Crypto"
challenge: "maas"
flag: "tjctf{per_mendacium_ad_veritatem}"
teknik: "Invalid-curve attack — oracle tidak validasi titik ada di kurva; sweep B' untuk kumpulkan residu CRT"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# maas — TJCTF 2026 (Crypto)

## Deskripsi Singkat

Oracle-nya mengimplementasikan perkalian skalar pada `y² = x³ + 2x + 3` di atas `F_{10007}` — tapi tidak pernah memverifikasi bahwa titik yang disubmit benar-benar ada di kurva itu.

## Analisis & Eksploitasi

**Invalid-curve attack** standar: pilih `B'` mana pun sedemikian sehingga `y² = x³ + 2x + B'` punya group order prima kecil `N_i` (rumus penjumlahannya cuma memakai `A`, bukan `B`), bangkitkan generator `G_i` dari subgroup tersebut, query oracle dengan `G_i` untuk menerima `d·G_i`, lalu brute-force discrete log untuk memulihkan `d mod N_i`. Sapu `B' = 0, 1, 2, …` sampai kamu mengumpulkan cukup modulus prima berbeda agar CRT bisa memulihkan `d` penuh (39 residu, total 519 bit di kasus ini).

## Catatan

Flag-nya: *"per mendacium ad veritatem"* — "melalui kebohongan, menuju kebenaran" — sindiran yang pas.

## Flag

```
tjctf{per_mendacium_ad_veritatem}
```
