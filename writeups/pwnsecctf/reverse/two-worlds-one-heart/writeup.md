# Two Worlds, One Heart

## Informasi Challenge

| Item | Detail |
|---|---|
| Kategori | Reverse Engineering |
| Kesulitan | Easy |
| Poin | 194 |
| File | `portal33.exe` |
| Teknik utama | x86/x64 dual interpretation, Heaven's Gate, ROL/ROR inversion |
| Flag format | `pwnsec{...}` |

---

## 2.1 Gambaran Umum

Challenge ini menggunakan byte code yang sama tetapi dijalankan dan diinterpretasikan sebagai:

```text
x86 32-bit
```

dan:

```text
x86-64
```

Teknik perpindahan mode menggunakan pola yang dikenal sebagai:

```text
Heaven's Gate
```

Hal pentingnya:

```text
32-bit verifier → memeriksa 20 byte pertama
64-bit verifier → memeriksa 20 byte terakhir
```

Jadi seluruh flag 40 byte dapat dipulihkan dengan membalik operasi `ROL` dan XOR.

---

## 2.2 Analisis File

`portal33.exe` merupakan PE32 console executable untuk Intel i386.

Input harus memiliki panjang tepat:

```text
0x28 = 40 byte
```

Flag juga memiliki panjang:

```text
40 byte
```

Binary memiliki kode di sekitar:

```text
VA 0x401600
```

Byte yang sama harus dianalisis dengan dua mode CPU.

---

## 2.3 Verifier 32-bit

Bagian 32-bit menggunakan lima word 32-bit.

Bentuk persamaannya:

```text
T[i] = ROL32(word[i] XOR previous, 11)
```

dengan:

```text
previous = 0x1337c0de
```

untuk word pertama.

Setelah itu:

```text
previous = T[i-1]
```

Target:

```text
T0 = 0xCDBD7302
T1 = 0x30833D2E
T2 = 0xB310EA05
T3 = 0xDEF1B433
T4 = 0x1C3B640E
```

---

## 2.4 Membalik ROL

Karena:

```text
T = ROL32(word XOR previous, 11)
```

maka:

```text
ROR32(T, 11) = word XOR previous
```

dan:

```text
word = ROR32(T, 11) XOR previous
```

Implementasinya:

```python
word = ror(target, 11, 32) ^ previous
```

Setelah mendapatkan word:

```python
previous = target
```

Kemudian lanjut ke target berikutnya.

Dengan demikian lima word pertama dapat dipulihkan tanpa brute force.

---

## 2.5 Pergantian Mode ke 64-bit

Wrapper menggunakan `retf` dengan selector:

```text
0x33
```

untuk berpindah ke 64-bit.

Kemudian selector:

```text
0x23
```

digunakan untuk kembali ke 32-bit.

Inilah alasan mengapa analisis hanya sebagai PE32 biasa bisa melewatkan separuh verifier.

---

## 2.6 Verifier 64-bit

Dalam mode 64-bit, bagian kode yang sama mempunyai interpretasi berbeda.

Persamaan pertama:

```text
ROL64(
    qword0 XOR 0x5A33C0D313379090,
    19
)
=
0x87326027C52B7005
```

Persamaan kedua:

```text
ROL64(
    qword1 XOR 0x87326027C52B7005,
    29
)
=
0x7E6E88ADD6EBC7E2
```

Word terakhir:

```text
ROL32(
    word9 XOR 0xD6EBC7E2,
    13
)
=
0x5E929579
```

---

## 2.7 Recovery 64-bit

Sama seperti sebelumnya, gunakan `ROR`.

Untuk qword pertama:

```python
qword0 = (
    ror(target64_0, 19, 64)
    ^ key64
)
```

Qword kedua:

```python
qword1 = (
    ror(target64_1, 29, 64)
    ^ target64_0
)
```

Word terakhir:

```python
word_last = (
    ror(target32_last, 13, 32)
    ^ (target64_1 & 0xffffffff)
)
```

Kemudian gabungkan:

```text
5 × uint32
1 × uint64
1 × uint64
1 × uint32
```

Total:

```text
20 + 8 + 8 + 4 = 40 byte
```

---

## 2.8 Validasi

Solver tidak hanya mengambil immediate value dari binary.

Ia juga memverifikasi kembali seluruh persamaan.

Untuk 32-bit:

```python
rol(word ^ previous, 11, 32) == target
```

Untuk 64-bit:

```python
rol(qword0 ^ key64, 19, 64) == target64_0
```

dan seterusnya.

Jika seluruh kondisi benar, flag diterima.

---

## 2.9 Solver

Jalankan:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

Solver juga melakukan pemeriksaan opcode skeleton terlebih dahulu sehingga immediate tidak diperlakukan sebagai konstanta jika struktur instruksinya berubah.

Flag:

```text
pwnsec{h3_5p34k5_32_5h3_5p34k5_64_l0v3!}
```

---

## 2.10 Inti Pembelajaran

Kunci challenge ini adalah jangan menganggap sebuah byte sequence hanya memiliki satu disassembly.

Jika binary melakukan:

```text
retf
selector 0x33
```

maka region target harus dianalisis sebagai x86-64.

Prinsipnya:

```text
same bytes
   │
   ├── decode as x86
   │       └── verifier A
   │
   └── decode as x64
           └── verifier B
```

Karena operasi hanya menggunakan rotate dan XOR, verifier bersifat invertible.

---
