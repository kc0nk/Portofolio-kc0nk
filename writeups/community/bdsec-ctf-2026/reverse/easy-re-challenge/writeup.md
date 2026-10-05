---
ctf: "BDSec CTF 2026"
kategori: "Reverse Engineering"
challenge: "Easy RE Challenge"
flag: "BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}"
teknik: "ELF x86-64 unstripped dengan 4 cabang panjang-input; hanya cabang 41-byte asli, transform XOR+rol+aditif+permutasi dibalik dari expected buffer tertanam"
sumber: "https://github.com/Abdelkad3r/BDSecCTF-2026"
---

# Easy RE Challenge — BDSec CTF 2026 (Reverse Engineering, 80 poin)

## Deskripsi Singkat

ELF PIE x86-64 **unstripped**. Symbol table-nya masih punya `expected.0..3`, `key_part_a`, `key_part_b`. `main` menggerbangi empat panjang input (24, 26, 29, 41). Tiga cabang lebih pendek mengembalikan umpan yang meyakinkan — `AFLAG/BFLAG/CFLAG{...}`; hanya cabang 41-byte yang mencapai "Excellent work" dan cocok format `BDSEC{...}`.

## Analisis

Nama symbol memberitahu seluruh hipotesis awal: "pengecekannya bukan hash, ini perbandingan byte-array terhadap hasil transform input." Transform maju per-byte-nya:

```c
keyed   = input[i] ^ key_part_a[i%8] ^ key_part_b[i%8];
rotated = rol(keyed, (i%7)+1);
out[(13*i)%41] = (rotated + ((11*i)^0x23)) & 0xff;
```

Setiap tahap bisa dibalik: baca `expected.3` di `0x2420`, un-permute index output, kurangi suku aditif, `ror` rotasinya, XOR kembali dua byte key-nya. Dua kunci 8-byte-nya dibaca dari `0x2450` (`key_b`) dan `0x2458` (`key_a`) — symbol table menamainya langsung.

## Eksploitasi / Solusi

```python
for i in range(41):
    out_idx = (13 * i) % 41
    val = (expected_3[out_idx] - ((11 * i) ^ 0x23)) & 0xff
    rotated = val
    keyed = ror8(rotated, (i % 7) + 1)
    input_byte = keyed ^ key_part_a[i % 8] ^ key_part_b[i % 8]
    flag.append(input_byte)
```

```
BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}
```

## Catatan / Insight

**Pelajaran:** biarkan binary memberitahu ke mana harus melihat. `nm -an` langsung memunculkan `expected.0..3` (target perbandingan empat cabang-panjang) dan `key_part_a/b` (dua blob kunci 8-byte). Ketika target perbandingan akhir sudah dipanggang di dalam binary dan setiap tahap antara input dan target bisa dibalik, bekerja mundur jauh lebih murah daripada pencarian input apa pun — tanpa brute force, tanpa instrumentasi dinamis, tanpa z3.

## Flag

```
BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}
```
