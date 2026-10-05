---
ctf: "BhAcKAri CTF 2026"
kategori: "Crypto"
challenge: "Eepy"
flag: "bhackariCTF{w0w_y0u_c4n_r34lly_sm1th}"
teknik: "RSA-2048 membocorkan 600 bit teratas prima p; 424 bit sisanya < N^(1/4) → Coppersmith small-roots via lattice Howgrave-Graham"
---

# Eepy — BhAcKAri CTF 2026 (Crypto)

## Deskripsi Singkat

> *"You're digging in the wrong place"* katanya, lalu menulis sesuatu di papan tulis dan pergi, sepertinya sedang **smithing**.

Flavour text-nya mengeja seluruh serangannya — *"smithing"* dan *"digging in the wrong place"* keduanya menunjuk ke **Coppersmith**, dan bingkai *eepy/dream/blackboard*-nya memberi tahu nilai bocorannya *parsial* (tidak lengkap).

## Analisis — Protokol

Connect ke `nc eepy.challs.ctf.bhackari.it 10000`, kirim `1`. Servis membangkitkan keypair RSA-2048 baru, mencetak `n`, `e = 65537`, dan sebuah "angka aneh yang aku yakin tidak lengkap". Secara empiris, angka itu selalu **persis 600 bit** — 600 bit teratas dari satu prima `p` dengan 424 bit terbawah dinolkan. Submit `p` yang benar, dapat flag.

**Kenapa Coppersmith.** `p` adalah prima 1024-bit; kita tahu 600 bit teratasnya persis. Tulis:

```text
p = p_high · 2^424 + x ,    0 ≤ x < 2^424
```

`p` membagi `N = pq`, jadi `f(x) := p_high · 2^424 + x` adalah polinomial **linier monic** dengan `f(x_0) ≡ 0 (mod p)`.

**Teorema small-roots Coppersmith:** untuk polinomial monic berderajat-`d` dengan akar `x_0` modulo divisor `p ≥ N^β`, kita bisa memulihkan `x_0` dalam waktu polinomial selama `|x_0| < N^(β²/d − ε)`. Di sini `d = 1`, `β = ½` (karena `p ≈ √N`), jadi batasnya `|x_0| < N^(1/4) ≈ 2^512`. Unknown kita paling banyak `2^424` — headroom nyaman (88 bit slack).

## Eksploitasi / Solusi — Lattice Howgrave-Graham

Bangun lattice integer dari polinomial yang lenyap mod `p^m` di `x = x_0`:

```text
g_i(x) = N^(m−i) · f(x)^i        untuk i = 0..m         (m+1 baris)
h_j(x) = x^j     · f(x)^m        untuk j = 1..t          (t baris)
```

Setiap `P_k(x)` ditulis ulang sebagai `P_k(xX)` di mana `X = 2^424` adalah batas `x_0`. Koefisiennya jadi baris lattice integer. LLL-reduce; lemma Howgrave-Graham menjamin vektor tereduksi terpendek berkorespondensi dengan polinomial `h(x)` yang `x_0`-nya adalah akar **atas integer**, bukan cuma modulo `p^m`.

Dengan `m = t = 6` (dimensi lattice 13), run selesai dalam ~setengah detik di laptop. Metode Newton presisi tinggi mengunci akar integer-nya; divisibilitas oleh `N` memverifikasinya.

```python
def coppersmith_high_bits(N, p_high, shift, m=6, t=6):
    X = 1 << shift
    P = p_high << shift                   # konstanta dari f(x)
    # f(x)^i = (P + x)^i, dibangun bertahap
    f_pow = [[1]]
    for _ in range(m):
        prev = f_pow[-1]
        new = [0] * (len(prev) + 1)
        for k, c in enumerate(prev):
            new[k]     += c * P
            new[k + 1] += c
        f_pow.append(new)
    polys = []
    for i in range(m + 1):
        polys.append([c * (N ** (m - i)) for c in f_pow[i]])
    for j in range(1, t + 1):
        polys.append([0] * j + list(f_pow[m]))
    B = IntegerMatrix(len(polys), m + t + 1)
    for r, poly in enumerate(polys):
        for j, c in enumerate(poly):
            B[r, j] = int(c) * (X ** j)
    LLL.reduction(B)
    # … ekstrak akar integer, verifikasi N % p == 0 …
```

## Catatan / Insight

Flag-nya: *"wow you can really smith"* — permainan kata dari Coppersmith.

**Pelajaran untuk defender:** **jangan pernah mempublikasikan apa pun lebih dari `N` dan `e` kalau kamu tidak bisa menjamin kebocorannya di bawah `N^(1/(d·β))`.** Prefix 600-bit dari prima 1024-bit menyisakan 424 bit tidak diketahui, jauh di dalam batas Coppersmith `2^512` untuk kasus linier. Panduan produksi: kalau sistem *harus* membocorkan sebagian materi key (misalnya skema toleransi fault hardware), pastikan kebocorannya di bawah batas Boneh-Durfee atau Coppersmith untuk tuple `(e, d, β)`-mu.

## Flag

```
bhackariCTF{w0w_y0u_c4n_r34lly_sm1th}
```
