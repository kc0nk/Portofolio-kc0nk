# 1. License Validator

**Kategori:** Reverse Engineering  
**Target:** `nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30008`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

Challenge menyediakan binary validator yang menerima activation code 16-byte dalam bentuk 32 karakter hex. Service juga mencetak tiga blok encrypted license token dan memberikan maksimal 256 query validasi.

Petunjuk penting justru berada pada binary: master key ternyata dapat dipulihkan secara statis sehingga oracle 256 query tidak perlu digunakan.

## 1.1 Analisis Binary

Binary yang dianalisis adalah ELF x86-64 non-PIE, stripped. Fungsi penting yang diidentifikasi pada reversing:

```text
main        0x401130
transform   0x401830
make_key    0x4018e0
parse_hex   0x401910
```

Input diparse sebagai:

```text
32 hex characters
        ↓
16 bytes
```

Fungsi `parse_hex` membaca dua karakter hex sekaligus dan mengubahnya menjadi satu byte.

## 1.2 Transformasi S-box

Fungsi `transform` melakukan substitusi per byte menggunakan 16 S-box berbeda.

Secara matematis:

```text
T[i] = S_i(P[i])
```

Setelah substitusi, byte dipermutasi menurut:

```text
π = [
    0, 5, 10, 15,
    4, 9, 14, 3,
    8, 13, 2, 7,
    12, 1, 6, 11
]
```

Sehingga secara konseptual:

```text
C[j] = T[π[j]]
```

S-box berada di area sekitar:

```text
0x402320 .. 0x40331f
```

dengan ukuran:

```text
16 × 256 = 4096 bytes
```

Setiap row merupakan permutation `0..255`, sehingga secara teori seluruh transformasi dapat dibalik menggunakan inverse S-box.

## 1.3 Jalur `key:HEX`

Service menerima jalur khusus:

```text
key:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Jalur ini memanggil fungsi pembentuk master key. Reversing menunjukkan bahwa key tidak dihitung dari data runtime yang rumit, melainkan dari dua tabel statis:

```text
Table A @ 0x403320
d8ae8e4f6eac342fc231b7b08716eb3f

Table B @ 0x403330
e1a202321ceb00031a21b89fe861e65a
```

Key adalah XOR kedua tabel:

```text
A XOR B
= 390c8c7d7247342cd8100f2f6f770d65
```

Ini adalah inti kelemahan challenge: master key tertanam langsung di binary.

## 1.4 Membalik Encrypted Token

Tiga blok token yang diberikan service:

```text
62120902dbbeb68b93953fabb85bd022
e3ab8f02b8f6fb1fe4d4bc18177590c2
f402a3cc7ca25203be79a7042c04f3ff
```

Inverse permutation yang digunakan:

```text
tmp[0]  = C[0]
tmp[1]  = C[13]
tmp[2]  = C[10]
tmp[3]  = C[7]
tmp[4]  = C[4]
tmp[5]  = C[1]
tmp[6]  = C[14]
tmp[7]  = C[11]
tmp[8]  = C[8]
tmp[9]  = C[5]
tmp[10] = C[2]
tmp[11] = C[15]
tmp[12] = C[12]
tmp[13] = C[9]
tmp[14] = C[6]
tmp[15] = C[3]
```

Lalu setiap byte dikembalikan melalui inverse S-box:

```text
P[i] = S_i^{-1}(T[i])
```

Plaintext hasil dekripsi:

```text
43594245524c45414755457b6c316333
6e73335f6b33795f7233633076337233
647d0e0e0e0e0e0e0e0e0e0e0e0e0e0e
```

ASCII:

```text
CYBERLEAGUE{l1c3ns3_k3y_r3c0v3r3d}
```

`0e` merupakan padding PKCS#7 sebanyak 14 byte pada block terakhir.

## 1.5 Strategi Solving

Tidak diperlukan:

- brute force 256 query,
- Z3,
- differential cryptanalysis,
- known-plaintext attack.

Cukup lakukan:

```text
binary
  ↓
extract Table A dan Table B
  ↓
A XOR B
  ↓
master key
```

Kemudian key dapat dikirim ke service:

```text
key:390c8c7d7247342cd8100f2f6f770d65
```

## 1.6 PoC Sederhana

```python
#!/usr/bin/env python3

A = bytes.fromhex("d8ae8e4f6eac342fc231b7b08716eb3f")
B = bytes.fromhex("e1a202321ceb00031a21b89fe861e65a")

key = bytes(x ^ y for x, y in zip(A, B))

print("[+] master key =", key.hex())
print("[+] submit      =", "key:" + key.hex())
```

## 1.7 Hasil

```text
[+] master key = 390c8c7d7247342cd8100f2f6f770d65
[+] flag       = CYBERLEAGUE{l1c3ns3_k3y_r3c0v3r3d}
```

## Flag

```text
CYBERLEAGUE{l1c3ns3_k3y_r3c0v3r3d}
```

## Lessons Learned

Challenge ini menunjukkan bahwa custom crypto atau transformasi kompleks tidak otomatis aman. Bila material kunci disimpan langsung di `.rodata`, seluruh lapisan oracle bisa menjadi tidak relevan.

---
