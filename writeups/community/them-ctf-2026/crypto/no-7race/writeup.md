---
ctf: "THEM?! CTF 2026"
kategori: "Crypto"
challenge: "No 7race"
flag: "THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}"
teknik: "a << 77777 berakhir dengan sufiks 155-digit → CRT mod 10^155 = 2^155 · 5^155, invers mod 5^155"
---

# No 7race — THEM?! CTF 2026 (Crypto)

## Deskripsi Singkat

`challenge.py` membaca `flag.txt` sebagai integer big-endian `a`, menghitung `b = a << 77777`, mengonversinya jadi string desimal, dan menggerbangi eksekusi dengan sufiks desimal 155-digit yang tetap. Tidak ada yang dicetak; constraint-nya *adalah* soalnya.

## Analisis

`b.endswith(target_decimal_155)` bisa ditulis ulang menjadi:

```text
a · 2^77777 ≡ target  (mod 10^155)
```

Memfaktorkan `10^155 = 2^155 · 5^155` dan menerapkan CRT (Chinese Remainder Theorem):

- **mod 2^155.** `2^77777 ≡ 0 (mod 2^155)` karena `77777 ≫ 155`. Constraint-nya memaksa `target ≡ 0 (mod 2^155)` (yang dipenuhi sufiks di handout) tapi *tidak memberi tahu apa-apa* soal `a` — nilai `a` apa pun berhasil modulo `2^155`.
- **mod 5^155.** `gcd(2, 5) = 1`, jadi `2^77777` invertible. Hitung `inv = pow(2, -77777, 5**155)`, lalu `a ≡ target · inv (mod 5^155)`.

`5^155 ≈ 2^359.7`, sementara flag ≤ 50 byte = `2^400`. Kelas residu mod `5^155` mengandung tepat satu representatif *kecil*; ubah jadi byte.

## Eksploitasi / Solusi

```bash
$ ./solve.py
[+] target has 155 decimal digits
[+] working modulus is 10^155 = 2^155 · 5^155
[+] recovered a mod 5^155: 32 bytes
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```

## Catatan / Insight

Flag-nya terbaca "number theorem is fun" (teorema bilangan itu menyenangkan).

**Pelajaran untuk defender:** constraint berbentuk *"integer besar ini dikali `2^k` berakhir dengan digit-digit ini"* adalah persamaan modular atas `10^N`. Faktorisasi `10^N = 2^N · 5^N` ditambah CRT ditambah invertibilitas multiplikatif dari `2` modulo `5^N` adalah resep standar. Mengenali resep ini adalah keseluruhan soalnya.

## Flag

```
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```
