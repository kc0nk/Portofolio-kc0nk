---
ctf: "BYUCTF 2026"
kategori: "Crypto"
challenge: "Hurtful"
flag: "byuctf{cuz_st3r30typ3s_hurt_92de04}"
teknik: "RSA e=3 dengan prefix known 122-byte → pemulihan small-root Howgrave-Graham/Coppersmith"
---

# Hurtful — BYUCTF 2026 (Crypto)

## Deskripsi Singkat

Handout-nya mengenkripsi `"Congrats on making it all the way here. … just find the flag: " + flag` dengan `e = 3`, `N` 2048-bit. Flag-nya pendek (~35 byte), tapi **prefix 122-byte-nya tetap dan diketahui**.

## Analisis

```text
ct  =  P · 256^L + x          (P diketahui, x = flag, L = panjang flag)
f(x) = (P · 256^L + x)^3 − c  punya akar kecil x_0 di atas Z_N
```

Dengan `log₂(X) ≈ 280` (batas flag) berbanding `log₂(N^{1/3}) ≈ 682`, akarnya duduk jauh di bawah batas Coppersmith — lattice 13×13 (`m=4, t=1`) memulihkannya setelah satu pass LLL.

## Eksploitasi / Solusi

```
byuctf{cuz_st3r30typ3s_hurt_92de04}
```

## Catatan / Insight

**Pelajaran untuk defender:** `e=3` ditambah relasi struktural *apa pun* antar plaintext (prefix diketahui, relasi diketahui antara dua pesan, pesan yang berhubungan secara polinomial) runtuh ke Coppersmith. Pakai OAEP, atau minimal `e=65537`. Kalimat di dalam flag — *"cuz stereotypes hurt"* (karena stereotip itu menyakitkan) — adalah pelajarannya sendiri, dicat di pintu.

## Flag

```
byuctf{cuz_st3r30typ3s_hurt_92de04}
```
