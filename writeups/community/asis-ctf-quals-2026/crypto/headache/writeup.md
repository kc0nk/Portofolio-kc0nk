---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Headache"
flag: "ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}"
teknik: "PRF softmax-attention tiga-head menyamar sebagai 'Hamiltonian'; oracle float64 tanpa noise diselesaikan dengan Levenberg-Marquardt + Jacobian analitik, dipipeline dan di-restart paralel"
---

# Headache — ASIS CTF Quals 2026 (Crypto, Medium)

## Deskripsi Singkat

"Non-Linear Hamiltonian Authenticator"-nya berbalut kosakata fisika — `coupling_tensors`, `partition_fn`, `boltzmann_weights`, `gauge_shift` — tapi einsum intinya menggulung jadi layer softmax-attention tiga-head.

## Analisis — Skemanya

Tujuh ronde masing-masing membangkitkan ulang matriks rahasia `A[c]` (4×4) dan `B[c]` (panjang-4) untuk `c in 0..2`. Untuk sequence `X` berbentuk `(L, 4)` dengan `x_tail = X[-1]`, tag-nya:

```
T(X) = Σ_c softmax_i( X[i] . (A[c] . x_tail) ) . ( X[i] . B[c] )
```

Budget per-ronde 1200 query `eval` (masing-masing delay server-side 0.03s), lalu perintah `challenge` mengeluarkan 6 sequence acak dan menuntut tag-nya dengan toleransi `1e-6`. Jendela koneksi total sekitar 120 detik.

**Pemulihannya.** Oracle-nya **eksak**: `float64`, tanpa noise, deterministik. Kandidat `(A', B')` yang mereproduksi tag pada ~150 sequence generik mereproduksi `T` di mana pun. Jadi tujuannya bergeser dari *temukan rahasianya* jadi *temukan kembaran fungsional mana pun*.

Dua observasi struktural membuat fit-nya mudah dikondisikan: **`B` linier diberikan `A`** — bobot softmax `w_c` hanya bergantung pada `A`, dan `T = Σ_c (w_c . X) . B[c]`. Jacobian block untuk `B[c]` cuma `w_c . X`. **Jacobian analitik**: turunan softmax `d w_m/d e_n = w_m(δ_mn − w_n)` runtuh bersih.

Levenberg-Marquardt atas seluruh 60 parameter (`3×16 + 3×4`) dengan Jacobian analitik, divektorisasi lintas query, mendarat di `rmse ~ 1e-15` di basin benar dan `> 1e-3` di basin lain.

**Membuatnya muat dalam koneksi.** Dua perbaikan engineering: **pipeline query eval** (tulis semua baris, flush, baru baca semua respons — memangkas fase query jadi kira-kira delay server-side saja plus satu RTT), dan **restart LM paralel** lintas core CPU, berhenti di `rmse < 1e-7` pertama. Total wall time lintas 7 ronde: ~70 detik, nyaman di dalam budget koneksi.

## Eksploitasi / Solusi

Setiap `max_err` ronde pada sequence challenge adalah `~1e-15`, sembilan orde magnitude di bawah toleransi `1e-6`.

## Catatan / Insight

**Kosakata bukan keamanan.** "Hamiltonian coupling tensors" dan "partition function" adalah skor attention dan normalizer softmax. **Oracle deterministik tanpa noise adalah hadiah** — mengubah key recovery jadi curve fitting dan mereduksi tujuan dari "temukan rahasia" jadi "temukan kembaran fungsional mana pun". Dan **constraint interaktif adalah bagian dari kripto-nya**: kesulitan sungguhan di sini adalah manajemen budget (pipelining + restart paralel) untuk memuat tujuh sistem 60-parameter independen dalam satu koneksi berbatas waktu.

## Flag

```
ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```
