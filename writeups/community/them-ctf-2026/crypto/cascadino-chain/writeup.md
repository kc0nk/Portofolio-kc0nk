---
ctf: "THEM?! CTF 2026"
kategori: "Crypto"
challenge: "Cascadino Chain"
flag: "THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}"
teknik: "Closed cycle 4-tahap kunci XOR; crib format flag (THEM ⊕ c1[0:4]) memecah rantainya"
---

# Cascadino Chain — THEM?! CTF 2026 (Crypto)

## Deskripsi Singkat

Empat ciphertext hex dengan panjang sama (masing-masing 42 byte):

```text
c1 = 36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012
c2 = 0e021b000e021b00…  ← periode 4
c3 = 180504021805040218…← periode 4
c4 = 2020202020 + terlihat acak
```

## Analisis

Strukturnya adalah closed XOR loop:

```text
c1 = flag ⊕ k1
c2 = k1   ⊕ k2
c3 = k2   ⊕ k3
c4 = k3   ⊕ flag
```

Sehingga `c1 ⊕ c2 ⊕ c3 ⊕ c4 == 0`, dan klaim si pembuat soal ("there's no way in" — tidak ada jalan masuk) secara teori-informasi memang jujur: hanya dengan `c1..c4`, kamu tidak bisa memulihkan flag tanpa satu constraint eksternal.

Constraint eksternalnya adalah **format flag**:

```python
k1 = bytes(a ^ b for a, b in zip(c1[:4], b"THEM")) = b"bozo"
flag = bytes(a ^ b for a, b in zip(c1, b"bozo" * 11)) = "THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}"
```

Kunci lainnya juga runtuh menjadi lelucon:

```text
k2 = "lmao"
k3 = "them"
```

## Eksploitasi / Solusi

Cukup XOR-kan 4 byte pertama `c1` dengan `"THEM"` untuk mendapatkan `k1`, lalu XOR seluruh `c1` dengan `k1` yang diulang.

## Catatan / Insight

**Pelajaran untuk defender:** XOR adalah inversnya sendiri, jadi *cycle* apa pun dari enkripsi XOR menjumlahkan menjadi nol dengan cara yang sama seperti `a − b + b − a == 0`. Enkripsi XOR berlapis-lapis tidak menambah keamanan terhadap penyerang yang punya crib known-plaintext sepanjang satu kunci saja — sekalipun rantai kuncinya jauh lebih panjang.

## Flag

```
THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}
```
