# Crystal Grid — Writeup

> **Kategori:** Cryptography  
> **Teknik:** Module-LWE, Ring-LWE style arithmetic, Negacyclic Convolution, Lattice Reduction, LLL, Kannan Embedding  
> **Target:** Offline — data terdapat di `challenge.py`  
> **Format Flag:** `CYBERLEAGUE{...}`

---

## 1. Deskripsi Challenge

Challenge **Crystal Grid** bercerita tentang tim survei mineral yang menghilang dan meninggalkan sebuah grid numerik yang digunakan untuk menyimpan data komposisi mineral.

Deskripsi:

```text
Dr. Petra's survey team went dark, and their last transmission from the northern site arrived as a strange numeric grid. She had been encoding her mineral composition data with a scheme of her own design, still half-tuned when she disappeared. The rival lab has already had a go at it and come away with nothing. Recover her research before they get a second attempt at the raw data.
```

Tidak ada service `nc` atau web pada challenge ini. Seluruh parameter, public data, dan ciphertext berada di file:

```text
challenge.py
```

Flag yang diperoleh:

```text
CYBERLEAGUE{cr7st4l_gr1d_m1n3r4l_d3c0d3d_e6a1}
```

---

# 2. Analisis Awal

Challenge ini tidak menggunakan primitive klasik seperti:

```text
RSA
AES
DES
XOR
Feistel
```

melainkan konstruksi **Module-LWE kecil** yang dibuat agar dapat diserang dengan lattice reduction.

Secara konsep, challenge menggunakan bentuk:

\[
\mathbf{b}=A\mathbf{s}+\mathbf{e}\pmod q
\]

dengan:

- `q = 67`
- ring:

  \[
  R_q=\mathbb{Z}_{67}[x]/(x^8+1)
  \]

- `k = 2`

Artinya:

```text
1 elemen ring = polynomial derajat < 8
2 elemen ring = vector dimension 2
```

Karena setiap polynomial memiliki 8 koefisien, secret total memiliki:

```text
2 × 8 = 16 koefisien
```

---

# 3. Struktur Matematika

## 3.1. Ring

Ring yang digunakan adalah:

\[
R_q=\mathbb{Z}_{67}[x]/(x^8+1)
\]

Konsekuensinya:

\[
x^8=-1
\]

bukan:

\[
x^8=1
\]

Ini penting ketika melakukan perkalian dua polynomial karena operasi convolution-nya bersifat **negacyclic**.

---

## 3.2. Dimensi

Parameter:

```text
n = 8
k = 2
q = 67
```

Maka:

```text
k × n = 16
```

koefisien secret.

Jika:

```text
s = (s0, s1)
```

dan:

```text
e = (e0, e1)
```

maka setiap `s_i` dan `e_i` adalah polynomial berderajat maksimal 7.

---

# 4. Key Generation

Bentuk public relation adalah:

\[
\mathbf{b}=A\mathbf{s}+\mathbf{e}\pmod q
\]

dengan:

```text
A ∈ Rq^(2×2)

s ∈ Rq^2

e ∈ Rq^2
```

`A` adalah public matrix.

Secret:

```text
s
```

dan error:

```text
e
```

bersifat kecil.

Dalam challenge ini keduanya menggunakan distribusi ternary:

```text
{-1, 0, +1}
```

atau secara ringkas:

```text
η = 1
```

---

# 5. Kenapa Parameter Ini Lemah?

Skema LWE/Module-LWE mendapatkan keamanannya dari kombinasi:

```text
dimensi besar
+
secret/error yang kecil
+
modulus yang sesuai
```

Challenge ini sengaja memakai parameter yang sangat kecil.

### 5.1. Dimensi sangat kecil

Total secret hanya:

```text
16 koefisien
```

sehingga secara scalar problem-nya sangat kecil dibanding parameter cryptosystem modern yang dirancang secara serius.

---

## 5.2. Secret dan error ternary

Setiap koefisien hanya berasal dari:

```text
-1, 0, +1
```

Sehingga secret dan error sangat pendek secara norm.

Misalnya, jika terdapat 32 koefisien gabungan dari `(s,e)`, panjang Euclidean tipikalnya hanya beberapa satuan.

---

## 5.3. Modulus kecil

```text
q = 67
```

merupakan modulus yang sangat kecil.

Hal ini membuat embedded short vector lebih mudah dibedakan dari vector random pada lattice.

---

# 6. Kenapa Lattice Bisa Menemukan Secret?

Kunci utama serangan adalah fakta bahwa:

```text
s  kecil
e  kecil
```

Sementara public relation:

\[
b=Ms+e\pmod q
\]

mengandung `s` dan `e` sebagai hidden variables.

Kita dapat mengubah modular equation tersebut menjadi problem pencarian **short vector**.

Secara intuitif:

```text
public matrix / vector
        │
        ▼
modular relation
        │
        ▼
lattice embedding
        │
        ▼
short vector
        │
        ▼
secret + error
```

---

# 7. Mengubah Ring Multiplication Menjadi Matriks

Komputer tidak perlu bekerja langsung dengan polynomial jika kita flatten seluruh polynomial ke scalar vector.

Karena setiap polynomial mempunyai 8 koefisien:

```text
a0 + a1 x + ... + a7 x^7
```

kita representasikan sebagai:

```text
[a0, a1, ..., a7]
```

Untuk dua polynomial:

```text
a(x), b(x)
```

perkaliannya pada:

\[
\mathbb{Z}_{67}[x]/(x^8+1)
\]

adalah **negacyclic convolution**.

Karena:

\[
x^8=-1
\]

term yang wrap-around melewati derajat 7 mendapat tanda negatif.

---

## 7.1. Negacyclic Matrix

Untuk polynomial:

```text
a = [a0,a1,...,a7]
```

multiplication-by-`a` dapat direpresentasikan dengan matriks 8×8.

Secara konseptual:

```text
[a0  -a7  -a6  -a5  -a4  -a3  -a2  -a1]
[a1   a0  -a7  -a6  -a5  -a4  -a3  -a2]
[a2   a1   a0  -a7  -a6  -a5  -a4  -a3]
[...]
```

Bentuk persis indeksnya berasal dari aturan:

```text
(t - b) mod 8
```

dengan sign negatif apabila terjadi wrap-around.

Setelah seluruh block ring di-flatten:

\[
A \in R_q^{2\times 2}
\]

menjadi:

\[
M \in \mathbb{Z}_q^{16\times16}
\]

dan relation menjadi:

\[
b=Ms+e\pmod q
\]

dengan:

```text
s ∈ Z^16
e ∈ Z^16
b ∈ Z^16
```

---

# 8. Bentuk Scalar Problem

Setelah flatten:

```text
M : 16 × 16
s : 16 × 1
e : 16 × 1
b : 16 × 1
```

dan:

\[
b\equiv Ms+e\pmod q
\]

Kita ingin menemukan:

```text
s
```

dan:

```text
e
```

tanpa mengetahui keduanya.

Jika hanya menggunakan aljabar linear biasa, kita menghadapi:

\[
Ms+e=b+qz
\]

dengan `e` juga tidak diketahui.

Namun `e` sangat kecil dan `s` juga sangat kecil. Inilah informasi tambahan yang dimanfaatkan lattice reduction.

---

# 9. Primal Attack

Serangan yang digunakan adalah pendekatan **primal lattice attack** melalui embedding ala **Kannan**.

Tujuannya adalah membuat lattice yang mengandung short vector berbentuk:

\[
(s,-e,\pm1)
\]

Jika short vector ini ditemukan oleh LLL, bagian pertama langsung memberikan secret.

---

# 10. Konstruksi Lattice

Dimensi lattice:

```text
16 secret variables
+
16 error variables
+
1 embedding coordinate
```

total:

```text
33
```

Jadi lattice yang digunakan berdimensi:

\[
33\times33
\]

---

## 10.1. Basis Utama

Setiap secret variable memperoleh row:

\[
[e_j\mid M_{:,j}\mid0]
\]

untuk:

```text
j = 0 ... 15
```

Selain itu ditambahkan baris yang merepresentasikan faktor modulus:

\[
[0\mid q e_i\mid0]
\]

untuk masing-masing koordinat public vector.

Terakhir ditambahkan target row:

\[
[0\mid-b\mid1]
\]

---

# 11. Mengapa Vektor Target Pendek Muncul?

Karena:

\[
b=Ms+e-qz
\]

maka:

\[
Ms-b=-e+qz
\]

Jika kita mengambil kombinasi basis yang tepat, bagian modulus dapat dibatalkan dan kita memperoleh:

\[
(s,-e,\pm1)
\]

Karena:

```text
s_i ∈ {-1,0,1}
```

dan:

```text
e_i ∈ {-1,0,1}
```

maka vector:

\[
(s,-e,\pm1)
\]

memiliki norm sangat kecil.

Ini membuatnya menjadi kandidat short vector yang sangat menonjol.

---

# 12. Gaussian Heuristic

Dimensi embedded problem:

```text
32 short coordinates
+
1 embedding coordinate
```

Vector:

```text
(s,e)
```

memiliki norm sekitar:

```text
4.8
```

berdasarkan distribusi ternary.

Sementara perkiraan panjang vector random terpendek menggunakan Gaussian heuristic berada sekitar:

```text
≈ 11
```

untuk parameter challenge.

Perbandingan ini penting:

```text
short target ≈ 4.8
random shortest ≈ 11
```

Dengan gap tersebut, LLL dapat menemukan vector target tanpa perlu BKZ yang berat.

---

# 13. Kenapa LLL Cukup?

Pada parameter cryptosystem modern, LLL sering tidak cukup untuk problem LWE yang benar.

Tetapi challenge ini dibuat jauh lebih kecil.

Ada tiga alasan LLL bekerja:

```text
1. Dimensi hanya 33
2. Secret/error sangat kecil
3. q hanya 67
```

Akibatnya vector target sangat pendek dibanding struktur lattice keseluruhan.

Jadi:

```text
LLL
```

sudah cukup dan tidak memerlukan:

```text
BKZ
```

---

# 14. Hasil Secret

Setelah lattice direduksi, baris yang memiliki:

```text
last_coordinate = ±1
```

dicari.

Jika koordinat pertama:

```text
16 angka
```

dan bagian kedua:

```text
16 angka
```

semuanya berada dalam:

```text
{-1,0,1}
```

maka baris tersebut merupakan kandidat `(s,-e,±1)`.

Secret yang ditemukan:

```text
s = [
    -1,  1,  0,  1, -1,  0,  1,  0,
     1, -1,  0, -1, -1, -1,  0,  1
]
```

Jika dipisahkan menjadi dua polynomial:

```text
s0 = [-1, 1, 0, 1, -1, 0, 1, 0]

s1 = [1, -1, 0, -1, -1, -1, 0, 1]
```

---

# 15. Verifikasi Secret

Setelah secret ditemukan, jangan langsung menganggap hasil LLL benar.

Kita harus melakukan:

```text
A * s + e (mod q)
```

dan memastikan relation public key kembali.

Atau secara sederhana:

```text
secret candidate
        │
        ▼
reconstruct public relation
        │
        ▼
compare with b
        │
        └── match → valid
```

Selain itu error vector juga harus:

```text
e_i ∈ {-1,0,1}
```

sesuai distribusi challenge.

---

# 16. Proses Dekripsi

Setelah secret diketahui, ciphertext dapat didekripsi.

Bentuk dekripsi yang diberikan challenge:

\[
m=v-s^Tu
\]

Nilai ini dihitung modulo `q`.

Setelah itu setiap koefisien hasil dekripsi dibandingkan dengan threshold:

```text
|m_i| > 16
```

berarti:

```text
bit = 1
```

sedangkan nilai lainnya menjadi:

```text
bit = 0
```

Karena:

```text
floor(q/2) = 33
```

dan:

```text
q = 67
```

bit encoding dapat dipisahkan berdasarkan kedekatan hasil terhadap:

```text
0
```

atau:

```text
33
```

dalam representasi modular centered.

---

# 17. Bit ke Byte

Setiap karakter pesan dienkode sebagai:

```text
8 bit
```

Jadi setelah seluruh ciphertext didekripsi:

```text
bit[0:8]
bit[8:16]
bit[16:24]
...
```

masing-masing dikelompokkan menjadi satu byte.

Kemudian:

```python
int(bits, 2)
```

atau operasi bitwise yang setara digunakan untuk menghasilkan byte ASCII.

Setelah seluruh byte dikonversi:

```text
ASCII
  ↓
flag
```

---

# 18. Solver Workflow

Alur solver:

```text
challenge.py
    │
    ▼
ambil A, b, ciphertext
    │
    ▼
flatten ring → matrix 16×16
    │
    ▼
b = M s + e mod 67
    │
    ▼
bangun lattice 33×33
    │
    ▼
LLL
    │
    ▼
cari vector (..., ±1)
    │
    ▼
recover s
    │
    ▼
validasi s/e
    │
    ▼
decrypt ciphertext
    │
    ▼
reconstruct bytes
    │
    ▼
ASCII flag
```

---

# 19. Solver Minimal — Struktur

Snapshot shared chat menyebut solver yang digunakan membaca data langsung dari `challenge.py` dan menjalankan LLL dengan `sympy`.

Karena attachment `challenge.py` dan file solver asli tidak tampil dalam snapshot shared page, kode berikut ditulis sebagai **kerangka reproduksi** dari metode yang dijelaskan pada percakapan, bukan diklaim sebagai salinan byte-per-byte solver asli.

Struktur inti solver:

```python
#!/usr/bin/env python3

from sympy import Matrix
from sympy.polys.matrices import DomainMatrix
from sympy.polys.domains import ZZ


Q = 67
N = 8
K = 2


def centered(x):
    x %= Q

    if x > Q // 2:
        x -= Q

    return x


def negacyclic_matrix(poly):
    """
    Build the 8x8 multiplication matrix for
    Z_q[x] / (x^8 + 1).
    """

    M = [[0] * N for _ in range(N)]

    for t in range(N):
        for b in range(N):

            idx = (t - b) % N

            value = poly[idx]

            # Wrap around through x^8 = -1.
            if t < b:
                value = -value

            M[t][b] = value % Q

    return M


def flatten_A(A):
    """
    A is a 2x2 matrix of length-8 polynomials.

    Convert it into a scalar 16x16 matrix.
    """

    out = [
        [0] * (K * N)
        for _ in range(K * N)
    ]

    for block_i in range(K):
        for block_j in range(K):

            block = negacyclic_matrix(
                A[block_i][block_j]
            )

            for i in range(N):
                for j in range(N):

                    out[
                        block_i * N + i
                    ][
                        block_j * N + j
                    ] = block[i][j]

    return out


def build_lattice(M, b):

    dim_secret = K * N
    dim_error = K * N
    dim = dim_secret + dim_error + 1

    rows = []

    # Secret basis rows.
    for j in range(dim_secret):

        row = [0] * dim

        row[j] = 1

        for i in range(dim_secret):
            row[
                dim_secret + i
            ] = M[i][j]

        rows.append(row)

    # Modulus rows for the error side.
    for i in range(dim_error):

        row = [0] * dim

        row[
            dim_secret + i
        ] = Q

        rows.append(row)

    # Target row.
    row = [0] * dim

    for i in range(dim_error):
        row[
            dim_secret + i
        ] = -b[i]

    row[-1] = 1

    rows.append(row)

    return Matrix(rows)


def find_short_vector(reduced):

    for i in range(
        reduced.rows
    ):

        row = [
            int(
                reduced[i, j]
            )
            for j in range(
                reduced.cols
            )
        ]

        if abs(row[-1]) != 1:
            continue

        secret = row[:16]
        error = row[16:32]

        if all(
            x in (-1, 0, 1)
            for x in secret
        ) and all(
            x in (-1, 0, 1)
            for x in error
        ):
            return (
                secret,
                error,
                row[-1]
            )

    return None
```

---

# 20. LLL dengan SymPy

Pada shared analysis, lattice reduction dilakukan dengan `sympy`.

Secara konsep:

```python
L = Matrix(rows)

R = L.lll()
```

Setelah itu:

```python
result = find_short_vector(R)
```

Jika ditemukan:

```text
secret
error
±1
```

maka secret telah diperoleh.

---

# 21. Implementasi SageMath

Untuk environment yang sudah memiliki SageMath, LLL dapat dibuat lebih nyaman.

Contoh struktur:

```python
M = matrix(
    ZZ,
    rows
)

R = M.LLL()

for row in R.rows():

    if abs(row[-1]) != 1:
        continue

    secret = list(
        row[:16]
    )

    error = list(
        row[16:32]
    )

    if all(
        x in [-1, 0, 1]
        for x in secret
    ) and all(
        x in [-1, 0, 1]
        for x in error
    ):
        print(
            "secret =",
            secret
        )
```

Dalam kasus ini Sage sangat cocok karena:

```text
ZZ matrix
+
LLL
+
large integer arithmetic
```

sudah tersedia secara native.

---

# 22. Dekripsi Ciphertext

Setelah secret tersedia, lakukan:

\[
m=v-s^Tu
\]

untuk setiap ciphertext block.

Pseudocode:

```python
def decrypt_block(s, u, v):

    # s^T u
    prod = ring_dot(
        s,
        u
    )

    # m = v - s^T u
    m = [
        centered(
            v[i] - prod[i]
        )
        for i in range(8)
    ]

    return m
```

Kemudian decode setiap koefisien menjadi bit.

Contoh konsep:

```python
bits = []

for x in m:

    x = centered(x)

    if abs(x) > 16:
        bits.append(1)
    else:
        bits.append(0)
```

Setelah 8 bit terkumpul:

```python
value = 0

for bit in bits:
    value = (value << 1) | bit
```

kemudian:

```python
chr(value)
```

---

# 23. Semua Ciphertext

Shared analysis menyatakan terdapat:

```text
46 ciphertext blocks
```

yang didekripsi menggunakan secret yang diperoleh dari lattice.

Urutannya:

```text
ciphertext #1
ciphertext #2
...
ciphertext #46
```

masing-masing diproses lalu digabung menjadi stream bit/byte.

Setelah conversion ke ASCII, diperoleh plaintext flag.

---

# 24. Verifikasi Plaintext

Setelah hasil dekripsi menjadi bytes, validasi dengan format flag:

```python
assert plaintext.startswith(
    b"CYBERLEAGUE{"
)

assert plaintext.endswith(
    b"}"
)
```

Kemudian decode:

```python
print(
    plaintext.decode()
)
```

---

# 25. Hasil Solving

Secret yang berhasil ditemukan:

```text
s = [-1,1,0,1,-1,0,1,0 | 1,-1,0,-1,-1,-1,0,1]
```

atau dipisahkan:

```text
s0 = [-1, 1, 0, 1, -1, 0, 1, 0]

s1 = [1, -1, 0, -1, -1, -1, 0, 1]
```

Dengan secret tersebut, seluruh ciphertext berhasil didekripsi.

---

# 26. Flag

```text
CYBERLEAGUE{cr7st4l_gr1d_m1n3r4l_d3c0d3d_e6a1}
```

---

# 27. Root Cause / Weakness

Kelemahan challenge berada pada **parameter cryptographic yang sengaja dibuat terlalu kecil**.

Bukan karena Module-LWE atau Kyber modern secara umum dapat dipecahkan dengan mudah.

Masalahnya adalah:

```text
q = 67
n = 8
k = 2
secret ternary
error ternary
```

sehingga total problem hanya mempunyai:

```text
16 secret coefficients
16 error coefficients
```

dan short vector `(s,e)` sangat mudah dibedakan dari vector lattice biasa.

Secara praktis:

```text
small dimension
+
small modulus
+
small secret
+
small error
        ↓
weak lattice instance
        ↓
LLL
        ↓
recover secret
```

---

# 28. Kenapa Brute Force Tidak Ideal?

Secara teori, secret mempunyai:

```text
3^16
```

kemungkinan jika setiap koefisien hanya:

```text
{-1,0,1}
```

Nilainya:

\[
3^{16}=43\,046\,721
\]

Angka tersebut memang jauh lebih kecil daripada brute force cryptosystem normal, tetapi challenge memberikan struktur yang jauh lebih elegan melalui lattice.

Selain itu, kita juga harus memperhitungkan error vector.

Dengan demikian serangan lattice lebih sesuai dengan desain challenge.

---

# 29. Tools

Untuk challenge ini tool yang relevan:

```text
Python 3
SymPy
SageMath
LLL
```

Tool seperti:

```text
RsaCtfTool
```

tidak relevan karena challenge bukan RSA.

---

# 30. Lessons Learned

## 30.1. Parameter lebih penting daripada nama algoritma

Mendengar:

```text
Module-LWE
```

tidak otomatis berarti challenge aman.

Implementasi toy dengan:

```text
dimension sangat kecil
```

dapat runtuh total.

---

## 30.2. Ring arithmetic perlu diperhatikan

Kesalahan umum adalah menganggap:

```text
x^8 = 1
```

padahal challenge memakai:

```text
x^8 = -1
```

sehingga perkalian harus:

```text
negacyclic
```

dan wrap-around mendapatkan sign negatif.

---

## 30.3. Short vector adalah petunjuk serangan

Jika:

```text
secret kecil
error kecil
```

dan public relation berbentuk:

\[
b=Ms+e\pmod q
\]

maka lattice reduction adalah salah satu pendekatan pertama yang layak diuji.

---

## 30.4. LLL bisa sangat kuat pada toy parameters

Tidak semua lattice attack memerlukan:

```text
BKZ
```

Pada instance yang sengaja lemah, LLL sudah cukup untuk menemukan target.

---

# 31. Ringkasan Solve Chain

```text
challenge.py
      │
      ▼
Ambil A, b, ciphertext
      │
      ▼
Ring:
Z67[x]/(x^8 + 1)
      │
      ▼
Flatten polynomial multiplication
      │
      ▼
M ∈ Z67^(16×16)
      │
      ▼
b = M s + e (mod 67)
      │
      ▼
s,e ∈ {-1,0,1}
      │
      ▼
Kannan embedding
      │
      ▼
33 × 33 lattice
      │
      ▼
LLL
      │
      ▼
short vector:
(s,-e,±1)
      │
      ▼
Recover secret
      │
      ▼
Decrypt 46 ciphertext blocks
      │
      ▼
Recover bytes
      │
      ▼
ASCII
      │
      ▼
CYBERLEAGUE{...}
```

---

# 32. Ringkasan Parameter

| Parameter | Nilai |
|---|---:|
| Scheme | Mini Module-LWE |
| Ring | `Z₆₇[x]/(x⁸+1)` |
| `q` | `67` |
| `n` | `8` |
| `k` | `2` |
| Secret coefficients | `16` |
| Error coefficients | `16` |
| Secret distribution | `{-1,0,1}` |
| Error distribution | `{-1,0,1}` |
| Flattened matrix | `16×16` |
| Embedded lattice | `33×33` |
| Attack | Primal / Kannan Embedding |
| Reduction | LLL |
| Ciphertext blocks | `46` |
| Flag format | `CYBERLEAGUE{...}` |

---

# 33. Final Result

```text
CYBERLEAGUE{cr7st4l_gr1d_m1n3r4l_d3c0d3d_e6a1}
```

---

## Referensi Shared Chat

```text
https://claude.ai/share/6242eb12-95cf-4dcb-990c-6a2fec5f5249
```

> **Catatan reproduksi:** shared snapshot menyebut `challenge.py` dan solver `solve_crystal_grid.py` sebagai attachment, tetapi attachment tersebut tidak ikut ditampilkan pada shared page. Karena itu, bagian kode lattice/dekripsi di atas merupakan rekonstruksi metodologi dari isi percakapan, sedangkan parameter, secret, hasil LLL, dan flag mengikuti hasil verifikasi yang ditampilkan pada shared chat.
