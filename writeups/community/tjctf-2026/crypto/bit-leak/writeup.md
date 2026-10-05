---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Crypto"
challenge: "bit-leak"
flag: "tjctf{parity_isnt_privacy}"
teknik: "RSA parity oracle bergaya Bleichenbacher; 540 query merekonstruksi plaintext bit demi bit"
---

# bit-leak — TJCTF 2026 (Crypto)

## Deskripsi Singkat

RSA 512-bit dengan **parity oracle**: submit ciphertext `C'`, terima `Dec(C') mod 2`.

## Analisis & Eksploitasi

Submit `C_i = C · (2^e)^i mod n`. Karena `Dec(C_i) = 2^i · m mod n`, LSB yang dikembalikan adalah `(2^i · m mod n) & 1`, yang merupakan **bit `i−1` dari ekspansi biner `m/n`**. Submit 540 ciphertext semacam itu (di-pipeline ke satu socket flush), kumpulkan 540 bit, rekonstruksi:

```python
bits_str = "".join(str(b) for b in lsb_responses)
m = (n * (int(bits_str, 2) + 1)) >> 540
```

## Flag

```
tjctf{parity_isnt_privacy}
```
