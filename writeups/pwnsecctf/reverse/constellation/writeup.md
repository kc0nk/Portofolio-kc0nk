# Constellation

## Informasi Challenge

| Item | Detail |
|---|---|
| Kategori | Reverse Engineering |
| Kesulitan | Hard |
| File utama | `main.exe`, `flag.flag` |
| Format flag | `pwnsec{...}` |
| Teknik utama | Reed–Solomon / GF(256), reverse permutation, stream reconstruction, XOR keystream, filesystem hashing |

## 1.1 Gambaran Umum

`Constellation` menggunakan sebuah format container yang sengaja dibuat rumit.

Secara garis besar alurnya adalah:

```text
flag.flag
   │
   ├── container header
   ├── metadata erasure
   └── 256 shard per block
          │
          ▼
   inverse shard permutation
          │
          ▼
   Reed–Solomon erasure recovery
          │
          ▼
   materialization archive
          │
          ▼
   reorder record/chunk
          │
          ▼
   XOR stream
          │
          ▼
   filesystem archive
          │
          ▼
   SHA3-512 terhadap seluruh filesystem
          │
          ▼
   pwnsec{...}
```

Bagian yang paling penting bukan hanya Reed–Solomon. Walaupun shard dapat dipulihkan secara matematis, shard masih disimpan dalam **urutan fisik yang berbeda dari urutan logisnya**.

---

## 1.2 Analisis Binary

Dari analisis dengan IDA ditemukan beberapa fungsi penting:

```text
0x140033DF0  configure_paths
0x1400368C0  parse_materialization_plan
0x1400383A0  materialize
0x140039200  consume_stream_record
0x140032020  sort_or_shuffle_shards
0x140036540  build_xor_keystream
```

Fungsi `materialize` merupakan bagian penting karena menangani proses pembuatan container dan materialization plan.

Sedangkan:

```text
0x140032020
```

berhubungan dengan pengurutan shard berdasarkan key dari plan.

---

## 1.3 Struktur Container

Header dibaca sebagai:

```python
struct.unpack_from("<9I", blob)
```

Parameter penting yang ditemukan:

```text
magic        = 0xE70B1591
width        = 192
data_shards  = 224
parity_shards= 32
seed         = 0xC1028A4D
blocks       = 4
```

Artinya setiap block memiliki:

```text
224 data shard
 32 parity shard
----------------
256 shard total
```

Setiap shard berukuran:

```text
192 bytes
```

Setelah header terdapat metadata erasure:

```text
33 byte per block
```

Format sederhananya:

```text
[count][erased_index_0][erased_index_1]...[erased_index_n]
```

Kemudian dilanjutkan dengan payload:

```text
256 × 192 bytes
```

per block.

---

## 1.4 GF(256)

Reed–Solomon menggunakan GF(256) dengan primitive polynomial:

```text
0x11D
```

Field dibangun dengan generator:

```python
value = 1

for _ in range(255):
    field.append(value)
    value <<= 1

    if value & 0x100:
        value ^= 0x11D
```

Sehingga kita memperoleh 255 elemen non-zero:

```text
1, 2, 4, 8, ...
```

dengan reduksi menggunakan polynomial `0x11D`.

Untuk perkalian:

```python
def gf_mul(a, b):
    if not a or not b:
        return 0

    return FIELD[(LOG[a] + LOG[b]) % 255]
```

Sedangkan perpangkatan:

```python
def gf_pow(value, exponent):
    if exponent == 0:
        return 1

    if value == 0:
        return 0

    return FIELD[(LOG[value] * exponent) % 255]
```

---

## 1.5 Matriks Reed–Solomon

Matriks parity ternyata mengikuti pola:

```text
M[p,d] = (p + 1)^d
```

dengan operasi perpangkatan dilakukan di GF(256).

Dalam Python:

```python
matrix = bytes(
    gf_pow(parity + 1, data)
    for parity in range(32)
    for data in range(224)
)
```

Jadi:

```text
parity row 0 → 1^d
parity row 1 → 2^d
parity row 2 → 3^d
...
parity row 31 → 32^d
```

---

## 1.6 Masalah Shard Permutation

Pada awalnya mudah untuk menganggap:

```text
physical shard == logical shard
```

Namun asumsi tersebut salah.

Program mengurutkan shard menggunakan key dari sebuah **materialization plan**.

Relasi yang dipakai solver:

```python
permutation = sorted(
    range(256),
    key=lambda shard: (order[block_index * 256 + shard], shard)
)
```

Kemudian:

```python
for physical_index, logical_index in enumerate(permutation):
    shards[logical_index] = physical[physical_index]
```

Ini berarti payload fisik harus dipetakan kembali ke indeks logis sebelum Reed–Solomon digunakan.

### Bagaimana plan diperoleh?

Plan tidak langsung tersedia sebagai file biasa. Analisis runtime dilakukan untuk mengambil object plan dari memory proses.

Script seperti `scan_plan.py` digunakan untuk mencari struktur yang memiliki:

```text
width = 192
data_shards = 224
parity_shards = 32
```

dan vector:

```text
field
matrix
order
```

Dari plan tersebut diperoleh:

```text
plan_field.bin
plan_matrix.bin
plan_order.bin
plan_meta.json
```

---

## 1.7 Recovery Shard yang Terhapus

Misalkan data shard yang hilang adalah:

```text
D3
D7
D10
```

dan parity yang tersedia:

```text
P0
P1
P2
```

Kita memiliki sistem:

```text
P0 = a00 D3 + a01 D7 + a02 D10 + known_data
P1 = a10 D3 + a11 D7 + a12 D10 + known_data
P2 = a20 D3 + a21 D7 + a22 D10 + known_data
```

Semua operasi dilakukan di GF(256).

Kontribusi data yang masih tersedia dikurangi dari parity sehingga diperoleh:

```text
A × missing_data = residual
```

Kemudian matriks `A` diinvers.

Implementasi inversion menggunakan Gaussian elimination di GF(256).

Konsepnya:

```text
[A | I]
```

diubah menjadi:

```text
[I | A^-1]
```

Setelah inverse diperoleh:

```text
missing_data = A^-1 × residual
```

---

## 1.8 Validasi Hasil Recovery

Setelah inverse permutation dan Reed–Solomon recovery diterapkan, data mulai memiliki struktur yang valid.

Archive hasil recovery memiliki magic:

```text
0x029D5011
```

Dalam little-endian:

```text
11 50 9D 02
```

Ini merupakan validasi penting.

Jika permutation tidak diterapkan, magic archive tidak muncul.

Jadi magic tersebut berfungsi sebagai:

```text
known-plaintext check
```

untuk memastikan:

1. field arithmetic benar;
2. permutation benar;
3. erasure recovery benar.

---

## 1.9 Materialization Record

Archive berikutnya memiliki record marker:

```text
0xF12C04A7
```

Setiap record berisi informasi seperti:

```text
path_len
record_len
path
record
```

Record ternyata mempunyai struktur yang dapat digunakan untuk menemukan nomor chunk.

Hubungan pentingnya adalah:

```text
chunk_index =
    (record_word_1 & 0xffff) XOR 0x06D0
```

Ada total:

```text
471 chunk
```

dan index yang dihasilkan tepat mencakup:

```text
0 .. 470
```

masing-masing satu kali.

Jadi record tidak boleh diproses berdasarkan urutan fisik. Kita harus:

```python
chunks[index] = record_payload
```

lalu:

```python
encrypted = b"".join(
    chunks[index]
    for index in range(len(chunks))
)
```

---

## 1.10 XOR Keystream

Setelah seluruh chunk disusun kembali, payload belum menjadi filesystem.

Masih terdapat XOR stream.

Fungsi pencampur:

```python
def mix32(value):
    value &= 0xFFFFFFFF

    value = ((value ^ (value >> 16)) * 0x7FEB352D) & 0xFFFFFFFF
    value = ((value ^ (value >> 15)) * 0x846CA68B) & 0xFFFFFFFF

    return (value ^ (value >> 16)) & 0xFFFFFFFF
```

Seed awal:

```text
0x5E17E11D XOR 0x50524144
```

Kemudian state:

```python
seed = mix32(0x5E17E11D ^ 0x50524144)
state = mix32(seed ^ 0x9E3779B9)
```

Setiap dword keystream:

```python
state = mix32(
    output_offset + state + 0x6D2B79F5
)
```

Lalu hasilnya digunakan untuk XOR:

```python
plaintext[i] = encrypted[i] ^ keystream[i]
```

---

## 1.11 Filesystem Archive

Hasil dekripsi menghasilkan filesystem archive berukuran:

```text
60,288 bytes
```

SHA-256:

```text
e9cbf4038148531e1d0b2acb0071b868d1fa41427b2420fbaf55dab89a0d7456
```

Isinya:

```text
139 entries
42 directories
97 files
```

Ada sebuah file:

```text
flag.py
```

yang tidak ikut dihitung dalam digest.

---

## 1.12 Cara Flag Dihitung

Untuk directory digunakan:

```text
D || u32(name_len) || name
```

Untuk file:

```text
F || u32(name_len) || name
  || u64(body_len)
  || body
```

Entry kemudian diurutkan berdasarkan nama path.

Setelah itu semua data diberikan ke:

```text
SHA3-512
```

dan hasilnya dibungkus:

```text
pwnsec{<sha3-512>}
```

---

## 1.13 Solver

Solver melakukan seluruh pipeline:

```text
1. Parse container
2. Build GF(256)
3. Recover erased shards
4. Reverse physical/logical permutation
5. Parse materialization records
6. Recover chunk index
7. Reorder chunks
8. Generate XOR keystream
9. Decrypt filesystem
10. Parse filesystem entries
11. Sort entries
12. SHA3-512
13. Print flag
```

Jalankan:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

Output flag:

```text
pwnsec{c0d3ebc92d57e1db301dbf8a6a9595b3e003078fc977c204ab6ff6372353a6da60a423b3d9b57fd1c7618b976df1500f2d3b137d9b5e57e92909a140ae6ee99f}
```

## 1.14 Inti Pembelajaran

Kesalahan terbesar yang mungkin dilakukan pada challenge ini adalah langsung mengerjakan Reed–Solomon tanpa memikirkan permutation.

Urutan yang benar:

```text
physical storage
      ↓
inverse permutation
      ↓
logical shards
      ↓
Reed–Solomon recovery
```

Magic archive:

```text
0x029D5011
```

sangat berguna sebagai oracle untuk memvalidasi tahap tersebut.

---
