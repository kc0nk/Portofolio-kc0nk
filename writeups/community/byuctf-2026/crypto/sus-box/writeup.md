---
ctf: "BYUCTF 2026"
kategori: "Crypto"
challenge: "sus-box"
flag: "byuctf{if_you_used_a_llm_youre_missing_out_learning_a_really_cool_attack_!}"
teknik: "Cipher 1-round XOR-Sbox-XOR dengan k1 = MD5(k0); brute-force byte per-posisi lewat XOR dua blok"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# sus-box — BYUCTF 2026 (Crypto)

## Deskripsi Singkat

Cipher-nya adalah satu ronde dari:

```text
c[j] = S[ p[j] ⊕ k0[j] ] ⊕ k1[j]      di mana k1 = MD5(k0)
```

S-box 256-byte-nya **dipublikasikan di output**. Plaintext-nya diawali prefix tetap 37-byte `"I have a secret, please don't share: "`, jadi blok 0 dan 1 sepenuhnya diketahui.

## Analisis

XOR dua persamaan blok pada posisi byte yang sama dan `k1[j]` saling mencoret:

```text
S[p0[j] ⊕ k0[j]] ⊕ S[p1[j] ⊕ k0[j]]  =  c0[j] ⊕ c1[j]
```

Itu persamaan satu-byte dalam `k0[j]`. Brute 0..255 per posisi; verifikasi dengan `MD5(k0) == k1`. Dekripsi sisa ciphertext byte demi byte.

## Eksploitasi / Solusi

```
byuctf{if_you_used_a_llm_youre_missing_out_learning_a_really_cool_attack_!}
```

## Catatan / Insight

**Pelajaran untuk defender:** flag-nya sendiri adalah pelajarannya — serangan ini adalah XOR-cancel-lalu-brute, diferensial buku-teks dari cipher substitusi satu-ronde. Tanpa menemukan langkah pencoretan (cancellation) lebih dulu, tidak ada jalan pintas; tekniknya-lah yang menentukan.

## Flag

```
byuctf{if_you_used_a_llm_youre_missing_out_learning_a_really_cool_attack_!}
```
