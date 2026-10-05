---
ctf: "R3CTF 2026 (r3kapig)"
kategori: "Crypto"
challenge: "HEuristic"
flag: "r3ctf{H3URistIC-De1T@-15-H1dDen-iN-fu1LY_h0mom0rPh1C_encryption_schemes0}"
teknik: "Server Microsoft SEAL CKKS membocorkan 96 koefisien dengan noise 188-bit di atas modulus 240-bit; 95 persamaan modular approximate + filter baseline-noise memulihkan delta"
sumber: "https://github.com/Abdelkad3r/R3CTF-2026/tree/master/crypto/HEuristic"
---

# HEuristic — R3CTF 2026 (Crypto)

## Deskripsi Singkat

Server Microsoft SEAL CKKS. Keypair segar tiap koneksi, `delta` acak mod `q` (hasil kali lima modulus RNS 48-bit, jadi `q` ~240 bit). Kita diizinkan mengenkripsi satu plaintext, mendekripsi ciphertext sembarang dan membaca kembali 96 koefisien pertama hasil komposisi dengan noise aditif ~188 bit, lalu submit tebakan untuk `delta`.

## Analisis

**Langkah 1 — Baca persamaan kebocorannya.** Server membangun plaintext secara manual: `plain[i + j·coeff_count] = coeff_i · delta mod q_j`, lalu meng-NTT-encode, mengenkripsi, dan membiarkan kita mendekripsi. Dekripsi melakukan inverse NTT + komposisi RNS, lalu membocorkan 96 koefisien pertama hasil komposisi dengan `noise_bound = 5 << 185` (`B ≈ 2^187.3`). Jadi untuk setiap koefisien pilihan `m_i` kita amati:

```
leak_i = m_i · delta + noise_i mod q,   |noise_i| < B
```

`q` ~240 bit, `B` ~188 bit, jadi setiap kebocoran membawa sekitar 52 bit informasi tentang `delta`. Jauh lebih dari cukup untuk 95 sampel.

**Langkah 2 — Pilih set plaintext yang valid.** Pengecekan koefisien plaintext menolak apa pun dengan representative absolut di bawah `q/8`. Baseline `q/2` lolos bersih dan nyaman karena ini nilai terbesar yang diizinkan. Slot tambahan memakai `q/2 + 2^e` (masih dekat `q/2`, masih lolos) — 95 eksponen dipilih untuk tersebar di 0..192 bit.

**Langkah 3 — Coret baseline dengan pengurangan.** `leak_0 = base·delta + noise_0 mod q`, `leak_e = (base+2^e)·delta + noise_e mod q`. Selisihkan untuk membunuh suku besar `base·delta`:

```
d_e = leak_e − leak_0 mod q = 2^e·delta + (noise_e − noise_0) mod q,   |noise_e − noise_0| < 2B
```

95 persamaan modular approximate untuk `delta` yang sama.

**Langkah 4 — Interval refinement.** Setiap persamaan bilang `2^e·delta mod q` berada dalam `2B` dari `d_e`. Mulai dari `[1, q)`, iriskan interval kandidat saat ini `[L, H]` dengan bayangan invers dari `[d_e − 2B, d_e + 2B]` di bawah perkalian dengan `2^e`. Enumerasikan sejumlah kecil wrap count `k`, hitung interval yang menyempit. Setelah 95 constraint, set kandidatnya runtuh jadi beberapa integer berdekatan (tiga di solve live).

**Langkah 5 — Filter baseline-noise memilih penyintas.** Batas `2B` konservatif karena setiap `d_e` mengandung `noise_e − noise_0`, dan `noise_0` *sama* di setiap persamaan. Untuk kandidat `delta`, hitung residual ter-center `r_e = centered(d_e − 2^e·delta mod q)`. Agar kandidat konsisten, harus ada satu `noise_0` sehingga `-B ≤ r_e + noise_0 ≤ B` untuk setiap `e`. `delta` yang benar meninggalkan irisan tak-kosong; kandidat salah yang berdekatan tidak. Di solve live, tiga penyintas interval-refinement tereduksi jadi tepat satu lewat filter ini.

## Eksploitasi / Solusi

```
[+] q = 6277101715473810179849235372514429772715831797744269418497
[+] ciphertext length = 262257
[+] got 96 leaked coefficients
[+] interval candidates: 3
[+] valid candidates: 1
[+] delta = 489875397824812687386690722568094443641738882699142192426
```

Submit `delta`; server mengembalikan flag.

## Catatan / Insight

Payload flag-nya — *"heuristic delta is hidden in fully homomorphic encryption schemes"* — melabeli kelasnya dengan tepat. Bug-nya bukan di SEAL sendiri; ada di keputusan pembuat challenge untuk membocorkan lebih banyak bit dari state terenkripsi dibanding yang disembunyikan noise budget. Library FHE mana pun yang mengimplementasikan CKKS dengan setia hanya seaman keputusan aplikasi tentang apa yang diungkapkan.

## Flag

```
r3ctf{H3URistIC-De1T@-15-H1dDen-iN-fu1LY_h0mom0rPh1C_encryption_schemes0}
```
