---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Mario"
flag: "ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}"
teknik: "64 report UOV semua di-mask vektor g yang sama → merentang W=O⊕span(g) 25-dimensi; quadratic form yang vanish di hyperplane O faktor jadi l·L, polar form-nya rank 2, kernel-nya memulihkan oil space"
sumber: "https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Crypto/Mario"
---

# Mario — ASIS CTF Quals 2026 (Crypto, Medium)

## Deskripsi Singkat

Public key-nya adalah instance Unbalanced Oil and Vinegar (UOV) tekstual-buku: 72 quadratic form dalam 96 variabel di atas `GF(16)`, semuanya vanish di subspace *oil* rahasia 24-dimensi `O`. Flag key diturunkan dari `O`, jadi memulihkan subspace itu adalah keseluruhan challenge-nya.

## Analisis — Skemanya

Parameter `n=96, m=72, d=24, s=64`, dengan `v=72` variabel vinegar. `monomial_scramble` memilih permutasi + skalar per-koordinat tak-nol dan menerapkan perubahan variabel yang sesuai — ini **hanya perubahan koordinat linier dan tidak lebih**; seluruh serangan berjalan di koordinat publik tanpa membalikkannya. Flag key adalah `HKDF(row_reduce(oil_basis), 32, salt, SHA256, context="MARIO")`.

**Kebocorannya.** `g` dipilih satu kali di luar loop, lalu **dipakai ulang di seluruh 64 report**:

```python
while True:
    g = r(n)
    if any(eval_quad(poly, g) for poly in polys):
        break                                          # <-- satu g, dipilih sekali

for _ in range(s):
    oil_vec = oil_embed(k_mat, r(d))
    mask    = secrets.randbelow(15) + 1
    reports.append(vec_add(oil_vec, vec_scale(g, mask)))
```

Setiap report adalah `r_i = o_i + λ_i·g` dengan `o_i ∈ O`. Jadi setiap report hidup di `W = O ⊕ span(g)`, `dim W = 25`. 25 report independen merentang `W`; generator-nya memberi 64.

**Di dalam `W`, form-nya terfaktorisasi.** `O` adalah hyperplane dari `W`, jadi `O = ker(l)` untuk suatu linear form `l` pada `W`. Setiap quadratic form yang vanish di `O` tidak punya suku tanpa `c_25`: **setiap dari 72 form, dibatasi ke `W`, terfaktorisasi sebagai produk dua linear form yang berbagi faktor `l`: `Q(c) = l(c)·L(c)`.** Polar form-nya `B(u,v) = l(u)L(v) + l(v)L(u)` punya **rank tepat 2** kapan pun `L` bukan kelipatan `l`, dengan `ker(B) = ker(l) ∩ ker(L) ⊂ O`, dimensi 23. Dua form berbeda memberi dua subspace 23-dim berbeda dari ruang 24-dim, dan irisannya merentang seluruh oil space.

## Eksploitasi / Solusi

```
[+] poly 0: polar rank 2, kernel dim 23, oil span now 23
[+] poly 1: polar rank 2, kernel dim 23, oil span now 24
```

Secara komputasi ini satu matrix triple-product per form (`W · S · Wᵀ` pada 25×25). Verifikasi dengan 1728 evaluasi (semua nol), `row_reduce` basis hasil pemulihan, jalankan HKDF generator, dekripsi AES-256-GCM. Tag GCM yang tervalidasi adalah bukti kriptografis bahwa subspace hasil pemulihan sama persis dengan milik generator.

## Catatan / Insight

**Hitung dimensinya dulu sebelum mengerjakan aljabar.** 64 vektor di ruang 96-dimensi hanya merentang 25 — amplop publik 25-dim yang mengandung seluruh rahasia 24-dim sebagai hyperplane. **Quadratic form yang vanish di hyperplane terfaktorisasi** sebagai `l·L`, polar form-nya turun ke rank 2, dan kernel-nya adalah slice hampir-lengkap dari rahasianya. **Data auxiliary adalah bagian dari attack surface**: public key-nya sudah sound; report tambahannya yang bocor. `g` yang diambil sekali di luar loop, bukan sekali per-report, adalah bug satu-baris yang meruntuhkan seluruh skema.

## Flag

```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```
