# skill issue '@aelmo'

> **Kategori:** Crypto  
> **Kesulitan:** Hard  
> **Platform:** PwnSec CTF 2026  
> **Flag:** `pwnsec{6a9c2ea004a8dee0}`

---

## 1. Pendahuluan

Challenge **skill issue '@aelmo'** merupakan challenge kriptografi yang menggunakan operasi matriks berukuran besar, modulus prima 2048-bit, serta beberapa teknik lattice reduction.

Sekilas, challenge terlihat sulit karena:

- modulus `p` tidak diberikan,
- matriks rahasia berukuran `16 × 16`,
- matriks tersebut kemudian diperbesar menjadi `48 × 48`,
- matriks dipangkatkan dengan eksponen yang sangat besar,
- hasil akhirnya hanya diberikan modulo `p`.

Namun terdapat kelemahan matematis yang sangat penting:

> Jika `Y = f(X)` untuk suatu polinomial `f`, maka `X` pasti commute dengan `Y`.

Artinya:

```text
XY = YX
```

Hubungan tersebut dapat digunakan untuk menghasilkan persamaan linear. Setelah modulus dihilangkan dari persamaan, hubungan tersebut dapat dimasukkan ke dalam lattice dan diselesaikan menggunakan **LLL**.

---

# 2. Source Challenge

Bagian utama challenge adalah:

```python
n = 16

flag = getenv(
    "FLAG",
    "pwnsec{????????????????????????????????????????????????}"
).encode()

p = getPrime(2048)
seed = urandom(16)
```

Challenge membuat:

- `p` = prima 2048-bit,
- `seed` = 16 byte acak,
- tiga diagonal `d0`, `d1`, `d2`,
- tiga matriks random `m0`, `m1`, `m2`.

Kemudian:

```python
x0 = mix(m0, d0)
x1 = mix(m1, d1)
x2 = mix(m2, d2)
```

dan ketiganya disusun menjadi matriks blok:

```python
x = stack(x0, x1, x2).change_ring(r)
```

Terakhir:

```python
cap = (
    x**4097
    + 3*x**257
    + 11*x**17
    + 42*x
    + 99*identity_matrix(r, 3*n)
)
```

Yang diberikan kepada attacker hanyalah `seed`, panjang flag, dan seluruh isi `cap`.

---

# 3. Memahami Fungsi `mix()`

Fungsi yang sangat penting adalah:

```python
def mix(m, d):
    return matrix(
        ZZ,
        n,
        n,
        [
            (1 + d[i] - d[j]) * ZZ(m[i, j])
            for i in range(n)
            for j in range(n)
        ]
    )
```

Jika:

```text
A = mix(M, d)
```

maka setiap elemen:

```text
A[i,j] = (1 + d[i] - d[j]) M[i,j]
```

Sedangkan `M[i,j]` berasal dari:

```python
raw = bytearray(urandom(n * n))
```

Jadi:

```text
0 ≤ M[i,j] ≤ 255
```

Ini merupakan constraint yang sangat kuat.

Jika kita berhasil mendapatkan `A` dan mengetahui `d`, maka:

```text
M[i,j] = A[i,j] / (1 + d[i] - d[j])
```

harus menghasilkan integer dalam rentang:

```text
0 ... 255
```

Constraint byte ini nantinya dipakai untuk memvalidasi hasil LLL dan CVP.

---

# 4. Struktur Matriks Rahasia

Fungsi `stack()` adalah:

```python
def stack(x, y, z):
    o = zero_matrix(ZZ, n)

    return block_matrix(
        ZZ,
        [
            [x, y, z],
            [o, x, y],
            [o, o, x]
        ],
        subdivide=False
    )
```

Misalkan:

```text
A = x0
B = x1
C = x2
```

maka:

```text
        ┌ A  B  C ┐
X   =   │ 0  A  B │
        └ 0  0  A ┘
```

Setiap blok memiliki ukuran:

```text
16 × 16
```

sehingga `X` memiliki ukuran:

```text
48 × 48
```

---

# 5. Struktur `cap`

Challenge menghitung:

```text
cap = f(X) mod p
```

dengan:

```text
f(X) = X^4097 + 3X^257 + 11X^17 + 42X + 99I
```

Karena `X` berbentuk upper-triangular block matrix, `f(X)` juga memiliki bentuk:

```text
        ┌ Y  Z  W ┐
F(X) =  │ 0  Y  Z │
        └ 0  0  Y ┘
```

dengan:

```text
Y = f(A)
```

Sedangkan `Z` dan `W` berasal dari interaksi antara `A`, `B`, dan `C`.

Dari output challenge kita bisa langsung memisahkan `cap` menjadi tiga blok:

```text
Y = cap[0:16, 0:16]

Z = cap[0:16, 16:32]

W = cap[0:16, 32:48]
```

---

# 6. Kelemahan Utama: Matriks Selalu Commute dengan Polinomialnya

Ini adalah inti challenge.

Kita memiliki:

```text
Y = f(A)
```

Untuk polinomial apa pun:

```text
f(A) = a0 I + a1 A + a2 A² + ...
```

maka:

```text
A f(A) = f(A) A
```

Karena itu:

```text
AY = YA mod p
```

atau:

```text
[A,Y] = 0 mod p
```

dengan notasi commutator:

```text
[A,Y] = AY - YA
```

Jadi:

```text
AY - YA = 0 mod p
```

Walaupun `p` tidak diketahui, kita mendapatkan banyak hubungan linear mengenai elemen-elemen `A`.

---

# 7. Mengubah Persamaan Modular Menjadi Persamaan Integer

Untuk setiap posisi `(i,j)`:

```text
(AY - YA)[i,j] = 0 mod p
```

berarti ada suatu integer `t[i,j]` sehingga:

```text
(AY - YA)[i,j] = t[i,j] p
```

atau:

```text
t[i,j] p =
Σk A[i,k]Y[k,j]
-
Σk Y[i,k]A[k,j]
```

Masalahnya sekarang adalah kita mempunyai:

```text
E1 = t1 p
E2 = t2 p
```

Kita tidak tahu `p`.

Tetapi kita dapat menghilangkan `p` dengan cross multiplication:

```text
t2 E1 - t1 E2 = 0
```

karena:

```text
t2(t1p) - t1(t2p) = 0
```

Dengan mengambil beberapa persamaan commutation yang sesuai, modulus rahasia dapat dieliminasi.

Hasilnya adalah hubungan integer yang melibatkan elemen-elemen `A`.

---

# 8. Mengapa LLL Bisa Digunakan?

Hubungan integer yang dihasilkan dapat ditulis dalam bentuk:

```text
u · v = 0
```

dengan `v` berisi elemen-elemen kolom matriks rahasia.

Karena nilai-nilai tersebut relatif kecil dibandingkan dengan modulus 2048-bit, kita dapat membuat lattice yang memiliki solusi pendek.

Secara konseptual bentuk lattice yang digunakan adalah:

```text
[I | u]
```

di mana:

- `I` adalah identity matrix,
- `u` berisi koefisien hasil eliminasi modulus.

Kemudian lattice direduksi menggunakan:

```text
LLL
```

LLL akan mencari basis baru yang memiliki vektor-vektor pendek.

Vektor pendek tersebut berisi informasi mengenai kolom matriks `A`.

---

# 9. Recovery Matrix `A`

Proses recovery `A` dilakukan per kolom.

Untuk setiap kandidat hasil LLL:

1. ambil vektor pendek,
2. interpretasikan sebagai kandidat kolom `A`,
3. coba kedua kemungkinan tanda,
4. coba faktor skala yang relevan,
5. gunakan fungsi `mix()` untuk memeriksa kandidat,
6. pastikan hasil pembagian merupakan byte.

Jika:

```text
candidate[i,j]
```

adalah kandidat elemen `A`, maka kita mencari:

```text
candidate[i,j]
------------------------- = m[i,j]
1 + d[i] - d[j]
```

dengan syarat:

```text
m[i,j] ∈ {0,...,255}
```

Kandidat yang tidak memenuhi constraint tersebut dibuang.

Setelah seluruh kolom berhasil direkonstruksi, kita mendapatkan bentuk dasar:

```text
A'
```

Tetapi belum seluruhnya selesai.

---

# 10. Masalah Common Scalar Shift

Persamaan:

```text
AY = YA
```

tidak dapat membedakan `A` dengan:

```text
A + λI
```

karena:

```text
(A + λI)Y
=
AY + λY
```

dan:

```text
Y(A + λI)
=
YA + λY
```

Sehingga:

```text
(A + λI)Y = Y(A + λI)
```

Artinya terdapat ambiguity berupa common scalar shift pada diagonal.

Jadi hasil LLL hanya menentukan bagian matrix tertentu, sedangkan perbedaan diagonal dan common shift harus diselesaikan kemudian.

---

# 11. Recovery Modulus `p`

Sekarang kita menggunakan hubungan commutation untuk mendapatkan `p`.

Misalkan bagian yang telah direcovery adalah `A'`.

Untuk elemen off-diagonal:

```text
[A,Y]i,j = 0 mod p
```

dapat ditulis:

```text
[A',Y]i,j
+
(A[i,i] - A[j,j])Y[i,j]
= 0 mod p
```

Sehingga:

```text
p | ([A',Y]i,j + ΔY[i,j])
```

dengan:

```text
Δ = A[i,i] - A[j,j]
```

Nilai diagonal berasal dari byte dan karena itu:

```text
-255 ≤ Δ ≤ 255
```

Kita dapat melakukan brute force pada nilai `Δ` yang sangat kecil.

Untuk sebuah kandidat `Δ`, kita memperoleh integer:

```text
g = [A',Y]i,j + ΔY[i,j]
```

Nilai tersebut harus habis dibagi `p`.

Jika kita mendapatkan dua nilai:

```text
g1 = k1 p
g2 = k2 p
```

maka:

```text
gcd(g1,g2)
```

biasanya mengandung `p`.

Dengan beberapa pasangan persamaan, faktor besar yang sama akan menjadi kandidat modulus.

---

# 12. Memastikan `p` Benar

Setelah mendapatkan kandidat modulus:

```text
p_candidate
```

kita melakukan beberapa pemeriksaan:

### Ukuran

```text
bit_length(p) == 2048
```

### Prima

```text
is_prime(p)
```

### Konsistensi commutation

```text
(A Y - Y A) mod p == 0
```

### Konsistensi dengan blok publik

```text
f(A) mod p == Y
```

Keempat pemeriksaan tersebut membuat kemungkinan false positive menjadi sangat kecil.

---

# 13. Recovery Diagonal `A`

Setelah `p` diketahui, perbedaan diagonal dapat diperoleh dari:

```text
[A',Y]i,j
+
(A[i,i] - A[j,j])Y[i,j]
= 0 mod p
```

Sehingga:

```text
A[i,i] - A[j,j]
=
-[A',Y]i,j / Y[i,j] mod p
```

Karena perbedaannya sebenarnya kecil:

```text
-255 ... 255
```

kita ambil representasi kecil dari hasil modular tersebut.

Dengan demikian kita mendapatkan semua:

```text
d[i] - d[j]
```

dan dapat merekonstruksi diagonal relatif.

Masih ada common shift:

```text
d[i] -> d[i] + λ
```

yang belum diketahui.

---

# 14. Menentukan Common Shift

Untuk setiap kandidat common shift `λ`, kita membentuk kembali:

```text
A
```

kemudian menghitung:

```text
f(A) mod p
```

dan membandingkannya dengan:

```text
Y
```

Hanya satu shift yang akan menghasilkan:

```text
f(A) mod p == Y
```

Setelah itu blok pertama:

```text
A = x0
```

telah berhasil direcovery secara lengkap.

---

# 15. Recovery Matrix `B`

Sekarang kita memanfaatkan struktur blok `X`.

Kita mempunyai:

```text
X = ┌ A B C ┐
    │ 0 A B │
    └ 0 0 A ┘
```

dan:

```text
F = ┌ Y Z W ┐
    │ 0 Y Z │
    └ 0 0 Y ┘
```

Karena:

```text
XF = FX
```

kita melihat blok `(1,2)`.

Dari perkalian blok:

```text
(XF)[1,2] = AZ + BY
```

sedangkan:

```text
(FX)[1,2] = YA + Z A
```

Dengan memperhatikan bentuk lengkapnya, diperoleh hubungan:

```text
YB - BY = AZ - ZA
```

Ini adalah **Sylvester-type matrix equation**.

Yang penting adalah semua bagian selain `B` sudah diketahui.

Jadi masalah nonlinear berubah menjadi masalah linear.

---

# 16. Sistem Linear untuk `B`

Matriks `B` berukuran:

```text
16 × 16
```

sehingga memiliki:

```text
256
```

unknown.

Diagonal diperlakukan sebagai parameter tersendiri.

Maka terdapat:

```text
256 - 16 = 240
```

unknown off-diagonal.

Sistem linear yang dibangun dari:

```text
YB - BY = AZ - ZA
```

mempunyai rank:

```text
240
```

untuk bagian off-diagonal.

Akibatnya seluruh off-diagonal `B` dapat ditulis sebagai fungsi affine dari 16 parameter diagonal.

Secara konsep:

```text
vec(B_off) = M · d_B + c
```

dengan:

```text
d_B = [B00, B11, ..., B15,15]
```

---

# 17. Menggunakan Constraint Byte pada `B`

Kita mengetahui:

```text
B[i,j]
=
(1 + d1[i] - d1[j]) m1[i,j]
```

dan:

```text
0 ≤ m1[i,j] ≤ 255
```

Setelah solusi affine diperoleh, setiap entry B memberikan constraint terhadap diagonal.

Masalah ini dapat dipandang sebagai instance kecil dari:

```text
LWE / bounded-error lattice problem
```

Kemudian dibuat lattice embedding.

Dimensi lattice yang digunakan solver adalah sekitar:

```text
40
```

dan kemudian dilakukan:

```text
LLL
```

---

# 18. Babai Nearest Plane

Setelah LLL menghasilkan basis yang lebih baik, digunakan algoritma:

```text
Babai nearest-plane
```

Tujuannya adalah mencari titik lattice yang paling dekat dengan target.

Secara sederhana:

```text
target
   │
   ▼
LLL-reduced basis
   │
   ▼
Babai nearest-plane
   │
   ▼
candidate diagonal bytes
```

Kandidat diagonal kemudian dimasukkan kembali ke solusi affine.

Hasil akhirnya adalah matrix:

```text
B
```

yang kemudian diverifikasi terhadap blok publik:

```text
Z
```

---

# 19. Recovery Matrix `C`

Untuk `C`, kita menggunakan blok `(1,3)` dari hubungan:

```text
XF = FX
```

Hasilnya:

```text
YC - CY = AW - WA + BZ - ZB
```

Pada tahap ini kita sudah mengetahui:

```text
A
B
Y
Z
W
```

sehingga sisi kanan sepenuhnya diketahui.

Dengan demikian kembali diperoleh persamaan Sylvester:

```text
YC - CY = known
```

Prosesnya sama:

1. bentuk sistem linear,
2. selesaikan off-diagonal,
3. sisakan diagonal sebagai parameter,
4. gunakan constraint byte,
5. bentuk lattice,
6. lakukan LLL,
7. gunakan Babai,
8. reconstruct `C`,
9. validasi dengan blok publik.

---

# 20. Posisi `sealed`

Flag tidak disimpan secara plaintext.

Challenge melakukan:

```python
sealed = xor(flag, mask(p, len(flag)))
```

Kemudian `sealed` dimasukkan ke dalam:

```python
m2 = slab(b"2", sealed)
```

Fungsi `slab()` menentukan posisi menggunakan:

```python
pos = int.from_bytes(
    stream(tag, 2),
    "little"
)

pos %= n * n - len(msg) + 1
```

Karena `seed` diketahui dari output challenge, posisi tersebut dapat dihitung kembali secara deterministik.

Setelah `C` berhasil direcovery:

```text
C
 ↓
mix^-1
 ↓
m2
 ↓
ambil sealed
```

---

# 21. Membalik Fungsi `mix()`

Untuk setiap elemen:

```text
C[i,j]
=
(1 + d2[i] - d2[j]) m2[i,j]
```

maka:

```text
m2[i,j]
=
C[i,j]
/
(1 + d2[i] - d2[j])
```

Setelah seluruh matrix `m2` diperoleh, kita mengambil `len(flag)` byte mulai dari posisi:

```text
pos
```

Hasilnya adalah:

```text
sealed
```

---

# 22. Membuat Ulang SHA-512 Mask

Fungsi mask challenge:

```python
def mask(k, out_len):
    kb = int(k).to_bytes(
        (int(k).bit_length() + 7) // 8,
        "big"
    )

    out = b""
    ctr = 0

    while len(out) < out_len:
        out += sha512(
            b"iLOVEtea"
            + len(kb).to_bytes(2, "big")
            + kb
            + seed
            + ctr.to_bytes(4, "little")
        ).digest()

        ctr += 1

    return out[:out_len]
```

Sekarang `p` sudah diketahui.

Kita juga mengetahui:

```text
seed
```

dan:

```text
flag_len
```

sehingga mask dapat dihitung persis.

Secara matematis:

```text
sealed = flag XOR mask
```

maka:

```text
flag = sealed XOR mask
```

---

# 23. Alur Serangan Lengkap

Keseluruhan exploit dapat diringkas sebagai berikut:

```text
                    cap = f(X) mod p
                            │
                            ▼
                ┌─────────────────────┐
                │ Pisahkan Y, Z, W    │
                └──────────┬──────────┘
                           │
                           ▼
                     Y = f(A)
                           │
                           ▼
                     AY = YA mod p
                           │
                           ▼
                Eliminasi modulus p
                           │
                           ▼
                         LLL
                           │
                           ▼
                       Recover A'
                           │
                           ▼
                  Cari diagonal diff
                           │
                           ▼
                       GCD → p
                           │
                           ▼
                 Recover diagonal A
                           │
                           ▼
                     f(A) = Y
                           │
                           ▼
                       Recover B
                           │
                           ▼
               Sylvester + LLL/CVP
                           │
                           ▼
                       Recover C
                           │
                           ▼
                 Sylvester + LLL/CVP
                           │
                           ▼
                      Recover m2
                           │
                           ▼
                    Extract sealed
                           │
                           ▼
                    mask(p, len(flag))
                           │
                           ▼
                  sealed XOR mask
                           │
                           ▼
                         FLAG
```

---

# 24. Kenapa Challenge Ini Bisa Dipecahkan?

Ada beberapa kelemahan yang saling melengkapi.

### 24.1 `f(x)` adalah polinomial dari `x`

Karena:

```text
cap = f(x)
```

maka:

```text
x cap = cap x
```

Hal ini memberikan banyak persamaan gratis.

### 24.2 Modulus tidak diketahui, tetapi dapat dieliminasi

Dua persamaan:

```text
E1 = t1 p
E2 = t2 p
```

dapat dikombinasikan menjadi:

```text
t2 E1 - t1 E2 = 0
```

sehingga `p` hilang.

### 24.3 Matriks asal hanya berisi byte

Nilai:

```text
m[i,j]
```

berada pada:

```text
0 ... 255
```

Constraint ini membuat pencarian lattice jauh lebih sempit.

### 24.4 Struktur upper-triangular

Matriks `48 × 48` sebenarnya bukan random matrix penuh.

Strukturnya:

```text
A B C
0 A B
0 0 A
```

memungkinkan recovery dilakukan secara bertahap:

```text
A → B → C
```

### 24.5 Flag menggunakan mask yang bergantung pada `p`

Setelah `p` berhasil direcovery, mask bukan lagi rahasia.

---

# 25. Tools yang Digunakan

Untuk mereproduksi solve, environment yang digunakan antara lain:

```text
Python
SageMath
python-flint
SymPy
mpmath
PyCryptodome
```

Komponen utama:

| Tool | Kegunaan |
|---|---|
| SageMath | operasi matematika dan matrix |
| python-flint | LLL |
| SymPy | manipulasi sistem matematika |
| Python | solver dan parsing |
| SHA-512 | mereproduksi mask |
| GCD | recovery modulus |
| Babai | nearest-plane CVP |

---

# 26. Bagian Penting Solver

Secara konseptual solver memiliki beberapa tahap utama:

```python
# 1. Parse output remote
seed = ...
flag_len = ...
cap = ...

# 2. Extract public blocks
Y = ...
Z = ...
W = ...

# 3. Recover A menggunakan commutation + LLL
A = recover_A(Y)

# 4. Recover p
p = recover_modulus(A, Y)

# 5. Resolve diagonal shift
A = resolve_A(A, p, Y)

# 6. Recover B
B = recover_B(A, Y, Z, p)

# 7. Recover C
C = recover_C(A, B, Y, Z, W, p)

# 8. Recover original m2
m2 = unmix(C, d2)

# 9. Extract encrypted flag
sealed = m2[pos:pos + flag_len]

# 10. Recreate mask
mask = make_mask(p, seed, flag_len)

# 11. Decrypt
flag = xor(sealed, mask)
```

Implementasi lengkap mengikuti persamaan matematis di atas.

---

# 27. Verifikasi Akhir

Recovery tidak boleh hanya berhenti ketika mendapatkan nilai yang terlihat benar.

Setiap tahap harus diverifikasi.

### Verifikasi `A`

```text
f(A) mod p == Y
```

### Verifikasi commutation

```text
A Y - Y A == 0 mod p
```

### Verifikasi `B`

Bangun kembali block `Z` dan cocokkan dengan output.

### Verifikasi `C`

Bangun kembali block `W` dan cocokkan dengan output.

### Verifikasi flag

Flag hasil decrypt harus sama dengan panjang:

```text
flag_len = 24
```

dan:

```text
pwnsec{...}
```

---

# 28. Hasil Akhir

Setelah seluruh proses recovery selesai:

```text
sealed
=
flag XOR mask(p)
```

berhasil dibalik menjadi:

```text
pwnsec{6a9c2ea004a8dee0}
```

## Flag

```text
pwnsec{6a9c2ea004a8dee0}
```

---

# 29. Kesimpulan

Challenge ini bukan sekadar masalah brute force terhadap matriks 48×48.

Kunci utamanya adalah mengenali struktur matematis:

```text
Y = f(A)
```

yang otomatis menghasilkan:

```text
AY = YA
```

Dari sana attack chain-nya adalah:

```text
commutation
    ↓
eliminasi modulus
    ↓
LLL
    ↓
recover A
    ↓
GCD
    ↓
recover p
    ↓
Sylvester equation
    ↓
recover B
    ↓
Sylvester equation
    ↓
recover C
    ↓
recover sealed
    ↓
SHA-512 mask
    ↓
XOR
    ↓
FLAG
```

Pelajaran paling penting dari challenge ini adalah bahwa **struktur aljabar yang terlihat sederhana dapat membocorkan informasi besar ketika dikombinasikan dengan constraint integer kecil dan lattice reduction**.

---

# 30. Flag

```text
pwnsec{6a9c2ea004a8dee0}
```
