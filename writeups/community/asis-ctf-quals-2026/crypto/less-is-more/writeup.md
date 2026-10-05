---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Less is More"
flag: "ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}"
teknik: "Bug iteration-skip 72% menimpa f[target] dengan indikator ronde sebelumnya, membuat satu leaf terungkap SEKALIGUS tertantang; voting 830 hit lintas 5963 record mengunci 7 permutasi code-equivalence"
---

# Less is More — ASIS CTF Quals 2026 (Crypto, Hard)

## Deskripsi Singkat

Parameter `P=827, N=548, K=274, T=345, W=75`, dengan `REAL=7` kunci asli tersembunyi di antara `SLOTS=17` slot publik. Kunci rahasia adalah `(p, d)` — permutasi kolom dan vektor skalar tak-nol; public key-nya adalah RREF dari matriks Cauchy yang dipermutasi-skala. Flag disegel di bawah `SHAKE-256("o" + pack_key(7 kunci asli))`.

## Analisis — Skema Signing-nya

`box.one(msg, serial)` adalah MPC-in-the-head cut-and-choose di atas Merkle tree 345 leaf. Challenge `b` (length-345, 75 entri tak-nol) menentukan indikator reveal `f = [int(b[i] != 0)]`. Untuk tiap leaf yang ditantang, respons mengungkapkan **set** `S = {i : p_x[i] ∈ v}` — tapi `v` diturunkan dari seed leaf tersembunyi, jadi secara jujur ini zero-knowledge.

**Bug-nya:**

```python
target = (37 * serial + 11) % T
if int.from_bytes(sha256(b'v' + root)[:2], 'big') % 100 < 72:
    f[target] = self.state[target]         # <-- indikator ronde sebelumnya
self.state = f
hit = [i for i in range(T) if b[i] and not f[i]]
```

72% waktu, signer menimpa `f[target]` dengan nilai signature **sebelumnya** di posisi itu. Ketika nilai sebelumnya `0` sementara challenge ronde ini punya `b[target] ≠ 0`, kita dapat **hit**: leaf yang benar-benar ditantang (punya respons) tapi ditandai `f=0` (seed-nya terungkap oleh cover). Terungkap dan tertantang seharusnya disjoint.

**Mendeteksi hit dari capture.** `_hit` dihapus sebelum disimpan, tapi setiap hit bisa direkonstruksi: `target = (37·serial+11) mod T`; hitung ulang `b = chal(cmt, salt, msg)` (hanya input publik), lewati record di mana `b[target]=0`; pulihkan `leaf[target]` dari cover path; konfirmasi dengan mencocokkan `label(cmt, leaf[target])`. Lintas 5963 record ini menemukan **830 hit**, semuanya cocok label, 105-128 per kelas.

**Memulihkan permutasi.** Untuk hit kelas `x`, kita tahu `v` dan response set `S`. Karena `|v|=|S|=K=N/2`, respons mengatakan `p_x[i] ∈ v` iff `i ∈ S`. **Voting**: untuk tiap `(x,i)` hitung berapa sering kolom itu di sisi yang diizinkan. `p_x[i]` yang benar diizinkan di setiap hit jujur (~110 vote); kolom lain diizinkan sekitar setengah waktu (~55 vote); 14% record fault ter-outvote. `argmax` memberi `p_x[i]`, margin vote minimum 21.

**Memulihkan diagonal.** Dengan `p_x` tetap, cocokkan pivot set `RREF(g[:,p_x])` terhadap pivot set tiap `M` publik, lalu selesaikan `d[j]/d[piv[t]] = W[t,j]/M[t,j]`.

## Eksploitasi / Solusi

```
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

## Catatan / Insight

**Cut-and-choose hanya zero-knowledge kalau kedua kasusnya tetap disjoint.** Seluruh skema bertumpu pada "tertantang berarti tersembunyi" dan "terungkap berarti tidak tertantang." Iteration skip-nya membiarkan satu leaf jadi terungkap **dan** tertantang sekaligus, dan satu kebetulan ini meruntuhkan properti ZK jadi kebocoran plaintext. **State yang dipakai ulang lintas signature adalah kerentanannya, bukan matematikanya** — kode Cauchy dan monomial masking-nya sound; `f[target] = self.state[target]` yang bocor. **Kebocoran set-membership bisa digabung**: 110 belahan acak seimbang per kelas mengunci permutasinya tanpa cryptanalysis lebih dari sekadar menghitung.

## Flag

```
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```
