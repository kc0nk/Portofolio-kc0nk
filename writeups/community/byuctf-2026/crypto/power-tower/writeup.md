---
ctf: "BYUCTF 2026"
kategori: "Crypto"
challenge: "Power Tower"
flag: "byuctf{eulers_phi_phunction_is_a_phun_phunction}"
teknik: "Multi-prime RSA (25 × 16-bit) dengan exponent tower right-associative 25-tingkat → reduksi rekursif Euler-φ"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# Power Tower — BYUCTF 2026 (Crypto)

## Deskripsi Singkat

Server live memakai multi-prime RSA di mana `n = ∏ p_i` dari 25 prima, masing-masing ≤ 2¹⁶, dengan exponent power-tower right-associative 25-tingkat:

```text
E = 73 ^ (6 ^ (11 ^ (90 ^ ... ^ 84)))
c = m^E mod n
```

## Analisis

Memfaktorkan `n` cuma trial division sampai 2¹⁶ — hitungan milidetik. Masalahnya berubah jadi menghitung `E mod (p_i − 1)` per prima, karena lewat CRT:

```text
m mod p_i = c ^ (E^-1 mod (p_i − 1))  mod p_i
```

Identitas lifting Euler mereduksi tower modulo `m`:

```text
a^b mod m = a^((b mod φ(m)) + φ(m)) mod m    (ketika b ≥ log₂ m)
```

Reduksi eksponen dalam tower mod `φ(m)`, eksponen dalam-dalam lagi mod `φ(φ(m))`, dan seterusnya. Setiap `φ(...)` murah karena modulus dibatasi 16 bit di puncak dan *menyusut* melalui setiap `φ` bersarang. 25 tingkat × 25 prima ⇒ ~600 komputasi φ yang trivial, 50 md wall-clock — masih jauh di bawah timeout 1 detik server.

## Eksploitasi / Solusi

```
byuctf{eulers_phi_phunction_is_a_phun_phunction}
```

## Catatan / Insight

**Pelajaran untuk defender:** multi-prime RSA dengan prima kecil itu rusak. Kalau kamu mempublikasikan exponent berbentuk power-tower dan berharap strukturnya jadi pagar, ingat itu juga *target lifting* — setiap φ bersarang menyusutkan modulus yang harus kamu reduksi.

## Flag

```
byuctf{eulers_phi_phunction_is_a_phun_phunction}
```
