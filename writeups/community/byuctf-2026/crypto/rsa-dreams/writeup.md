---
ctf: "BYUCTF 2026"
kategori: "Crypto"
challenge: "RSA Dreams"
flag: "byuctf{great_job_recovering_the_flag}"
teknik: "hint = p + q memberikan φ(n) = n − hint + 1 lewat satu pengurangan"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# RSA Dreams — BYUCTF 2026 (Crypto)

## Deskripsi Singkat

Handout mempublikasikan `n`, `e`, `c`, dan `hint = p + q`.

## Analisis

Aljabarnya tidak terelakkan:

```text
φ(n) = (p−1)(q−1) = pq − (p+q) + 1 = n − hint + 1
```

Hitung `d = e⁻¹ mod φ`, lalu `m = c^d mod n`. Satu baris kode solver.

## Eksploitasi / Solusi

```
byuctf{great_job_recovering_the_flag}
```

## Catatan / Insight

**Pelajaran untuk defender:** jangan pernah mempublikasikan turunan dari private key. `p + q`, `p − q`, dan `φ(n)` semuanya setara dengan `d`. Bahkan tanpa shortcut totient, hint yang sama tetap memfaktorkan `n` lewat `x² − hint·x + n = 0`.

## Flag

```
byuctf{great_job_recovering_the_flag}
```
