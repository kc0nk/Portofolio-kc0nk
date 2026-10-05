---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Sultan"
flag: "ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}"
teknik: "Module-LWE dengan hint floor(inner(A,u)/65000) berdampingan v=u+c·s; substitusi u=v-c·s mengubah tiap hint jadi constraint linier 7-bit pada s; Bai-Galbraith embedding + BKZ-30"
sumber: "https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Crypto/Sultan"
---

# Sultan — ASIS CTF Quals 2026 (Crypto, Medium-Hard)

## Deskripsi Singkat

Servis membangkitkan `secret_string` per-sesi dan membiarkan client mendownload `encrypt_sultan(secret_string)` sebagai `secret.enc` sampai 500 kali, lalu memverifikasi tebakan di `/api/verify`. Seluruh tugasnya adalah memulihkan rahasia sesi dari satu `secret.enc`.

## Analisis — Cipher-nya

Parameter `q=8380417, n=64, ℓ=1, m=70, t=16, b=65000, secret_bound=3`. Rahasianya satu polinomial `s ∈ R_q = Z_q[X]/(X^64+1)` dengan koefisien di `[-3,3]`. **Kunci adalah fungsi murni dari `s`.** Memulihkan `s` memberi `k = SHAKE256("SULTAN/key" || s)`, lalu keystream, lalu `secret_string = e XOR p`. Tag BLAKE2s membiarkan kita mengonfirmasi kandidat `s` secara offline.

**Kebocorannya.** Untuk tiap dari 70 sesi, record mempublikasikan `x`, `y`, `seed=x+y`, `u` (acak), `c = challenge sparse dari seed`, `v = u + c·s`, dan `hint = floor(inner(A,u)/b)` di mana `A = r(seed)`. `v` saja uniform (ter-mask oleh `u`); hint-nya adalah seluruh permainannya.

Karena `u = v - c·s`:

```
inner(A, u) ≡ inner(A, v) - inner(A, c·s)   (mod q)
```

Keduanya publik. Menulis `M_j·s = inner(A_j, c_j·s)` dan `a_j = inner(A_j, v_j)`, hint-nya terbaca:

```
M_j·s + r_j ≡ a_j - hint_j·b   (mod q),     r_j ∈ [0, b)
```

Dengan `T_j = (a_j - hint_j·b) mod q`, itu adalah **sampel LWE tekstual-buku** dengan rahasia kecil `s ∈ [-3,3]^64` dan error `r_j < 65000 << q`.

**Lattice-nya.** 70 sampel mengendalai 64 unknown; setiap hint membawa `log2(q/b) ≈ 7` bit, jadi ~490 bit mengunci rahasia yang entropinya cuma ~180 bit — sangat over-determined. Embedding Bai-Galbraith primal (Kannan) dimensi `n+m+1=135`, dengan koordinat rahasia diskalakan `Ws ≈ b/6` dan error dipusatkan di `b/2`. Vektor pendek uniknya meng-encode `(-s, r-b/2, 1)`. Gap uSVP ~3.7 di dimensi 135. LLL biasa tidak cukup; **progressive BKZ** — BKZ-30 memulihkan `s` dalam ~2 detik.

## Eksploitasi / Solusi

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```

## Catatan / Insight

**Jangan bocorkan bit tinggi dari mask yang juga membawa rahasia.** Mempublikasikan `floor(inner(A,u)/b)` berdampingan `v=u+c·s` mengubah setiap "hint komite" jadi persamaan linier pada `s` dengan error terbatas-`b`. **Parameter mainan adalah keamanan mainan**: `n=64, ℓ=1`, lebar rahasia 3 — jauh di bawah level Dilithium sungguhan mana pun, runtuh di bawah BKZ-30 dalam hitungan detik. Dan **kunci yang merupakan fungsi murni dari nilai yang bisa dipulihkan hanya sekuat nilai itu** — `k = SHAKE(s)` berarti satu solve lattice membuka seluruh cipher terautentikasi.

## Flag

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```
