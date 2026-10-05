---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Linchan"
flag: "ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}"
teknik: "Matriks rank-25 ditanam di setiap subspace GF(2) asli di antara 102 decoy; rank invarian terhadap change-of-basis dan transposisi; scan MinRank Gray-code 14 detik menemukan plant-nya"
---

# Linchan — ASIS CTF Quals 2026 (Crypto, Hard)

## Deskripsi Singkat

`linchan.py` meng-encode tiap matriks 32×32 di atas GF(2) sebagai 32 row-integer. Output-nya adalah **112 box**, masing-masing subspace m-dim dari `M_32(GF(2))`, disajikan dalam basis acak dan mungkin ditransposisi. Sepuluh box membentuk lima pasang konjugat `span(D) = S·span(C)·S⁻¹`. Flag dienkripsi di bawah ChaCha20Poly1305 yang dikunci SHAKE dari bentuk kanonik terurut lima `S`.

## Analisis — Plant-nya

`_b(m, True)` men-seed subspace asli dengan dua elemen dari `_h()` (rank tepat 25), sementara decoy uniform. Distribusi rank matriks 32×32 uniform di GF(2): `P(rank ≤ 25) ≈ 6.1×10⁻¹⁵ ≈ 2⁻⁴⁷·²`. Dua fakta membuat ini fatal: **rank adalah properti subspace, bukan basis** — `_o()` mengekspresikan ulang basis lewat change-of-basis acak, tidak mengubah set elemen subspace-nya. **Rank invarian terhadap konjugasi dan transposisi** — `rank(S·H·S⁻¹) = rank(H)` dan `rank(Hᵀ) = rank(H)`, jadi marker-nya bertahan ke box pasangannya dan bertahan terhadap koin-lempar transposisi.

**MinRank lewat eksaustif.** Setiap elemen setiap subspace bisa dienumerasikan langsung: 16.908.176 matriks total. Solver C menelusuri tiap subspace dalam urutan Gray-code (satu XOR 32-word per langkah) dan me-rank tiap elemen dengan eliminasi 32-langkah. Threshold 26 menjaga false positive minimal sambil menangkap semua plant:

```
[+] 112 box, 16.908.176 elemen subspace untuk discan
[+] MinRank: 20 matriks rank ≤ 26 di 10 box
[+] box asli per dimensi: {16: [...], 17: [...], 18: [...]}
```

14 detik. 20 hit, semuanya rank tepat 25, tepat dua per box, di tepat 10 box.

**Pairing.** Fingerprint invarian kesamaan yang bertahan terhadap transposisi: `fingerprint(H) = tuple(rank(H^k) for k in range(1, 13))`.

**Melinierkan `S`.** Plant-nya teridentifikasi kanonik di dalam subspace-nya (hanya elemen rank 25), menghilangkan unknown change-of-basis sepenuhnya. Kalau box A berisi `H_1, H_2` dan box B berisi `G_1, G_2`, maka `G_i = S·H_i·S⁻¹`. Unknown-nya sekarang cuma `S`: `X·H_1 = G_1·X`, `X·H_2 = G_2·X` — 2048 persamaan dalam 1024 unknown di atas GF(2), satu eliminasi Gauss. Ruang solusinya `S·Centralizer(H_1,H_2)`; dua matriks rank-25 acak membangkitkan seluruh aljabar matriks dengan probabilitas overwhelming, centralizer-nya `{0,I}`, jadi ruangnya satu-dimensi.

## Eksploitasi / Solusi

SHAKE bentuk kanonik terurut lima `S`, ambil 32 byte, jalankan ChaCha20-Poly1305 dengan 12 byte pertama ciphertext sebagai nonce. Tag Poly1305 yang tervalidasi adalah bukti kriptografis bahwa kelima matriks hasil pemulihan benar.

## Catatan / Insight

**Tanyakan apa yang bertahan terhadap obfuskasinya.** `_o()` terlihat menyembunyikan subspace, tapi change-of-basis mempertahankan setiap elemennya. **Distinguisher dan key-recovery seringkali observasi yang sama** — plant rank-rendah mengidentifikasi box asli, memasangkannya, dan mengunci korespondensi basisnya. **MinRank hanya sulit kalau ruangnya besar**; di `m ≤ 18` seluruh subspace muat dalam satu loop Gray-code dan argumen keamanannya menguap.

## Flag

```
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```
