# Gap Gap

> **Event:** PwnSec CTF 2026  
> **Kategori:** Crypto  
> **Kesulitan:** Medium  
> **Status:** Solved  
> **Flag format:** `pwnsec{...}`

## 1. Gambaran Umum

Challenge menggabungkan **Common Prime RSA** dengan kebocoran private exponent `d`. Nilai `p-1` dan `q-1` memiliki faktor prima besar yang sama, yaitu `g`, sementara 30 digit di tengah `d` sengaja dihilangkan.

Observasi kunci adalah adanya relasi modulo `g` yang melibatkan blok digit yang hilang, sedangkan `phi(N)` mempunyai faktor `g^2`. Dua akar kecil tersebut dapat dipulihkan menggunakan simultaneous modular lattice. Setelah `d` lengkap, continued fraction digunakan untuk mendapatkan `2g`, lalu faktor RSA dapat dihitung.

## 2. Relasi RSA

Challenge menghasilkan:

```text
p = 2*g*a + 1
q = 2*g*b + 1
lambda = lcm(p-1, q-1) = 2*g*a*b
e*d - 1 = k*lambda
```

`d_leak` berisi prefix 47 digit dan suffix 47 digit, sedangkan 30 digit di tengah diganti `*`.

Definisikan:

```text
G = 2*g
A = e*d - 1
```

Maka:

```text
A = k*G*a*b
```

## 3. Relasi Modulo Prime

Dengan mengurangi persamaan terhadap `p` dan `q`, diperoleh:

```text
A + b*k = b*k*p ≡ 0 (mod p)
A + a*k = a*k*q ≡ 0 (mod q)
```

Relasi ini menghubungkan nilai `d`, faktor bersama `g`, dan parameter kecil `a,b,k`.

## 4. Memodelkan Digit yang Hilang

Tulis private exponent sebagai:

```text
d = D0 + 10^47*x
0 <= x < 10^30
```

Karena `x` hanya 30 digit, ia cukup kecil untuk menjadi small root. Walaupun `g` sendiri tidak diketahui, kita dapat membangun dua polinomial linear yang memiliki akar kecil secara simultan:

```text
f1(x) = x + a1 ≡ 0 (mod g)
f2(y) = y + N + 1 ≡ 0 (mod g^2)
y = -(p+q)
```

Relasi kedua berasal dari:

```text
N + 1 - p - q = (p-1)(q-1) = 4*g^2*a*b
```

## 5. Simultaneous Modular Lattice

Bobot 1 dan 2 diberikan pada `f1` dan `f2`. Untuk setiap shift yang dipilih, bentuk:

```text
f1^i * f2^j * (N-1)^r
```

dibuat menghilang modulo pangkat `g` yang sesuai. Pada `t = 3`, kombinasi shift menghasilkan lattice integer berdimensi 27.

Setelah reduksi LLL, pasangan gcd dari polinomial yang telah direduksi mengekspos faktor linear:

```text
x - 629965031111793143531495543250
```

Jadi blok 30 digit yang hilang berhasil dipulihkan.

## 6. Melengkapi `d`

Blok tersebut dimasukkan kembali ke leak sehingga diperoleh `d` lengkap. Verifikasi dilakukan dengan memeriksa relasi RSA:

```text
2^(e*d - 1) mod N = 1
```

Dengan `d` lengkap, tahap selanjutnya adalah memfaktorkan `N`.

## 7. Mendapatkan `2g` dengan Continued Fraction

Gunakan constraint generasi:

```text
h = p*b + a = lambda + a + b
```

Dari relasi challenge diperoleh:

```text
N - 1 = G*h
G*(e*d-1) - k*(N-1) = -G*k*(a+b)
```

Sisi kanan relatif kecil dibandingkan produk utama. Karena `gcd(k,G)=1`, pecahan `k/G` muncul sebagai convergent continued fraction dari:

```text
(e*d-1)/(N-1)
```

Dengan demikian denominator 601-bit `G` dapat dipulihkan.

## 8. Memulihkan Faktor RSA

Setelah `G` dan `k` diketahui:

```text
lambda = (e*d-1)/k
a+b = h-lambda
ab = lambda/G
```

Kemudian hitung diskriminan:

```text
(a+b)^2 - 4ab
```

Diskriminan tersebut merupakan kuadrat sempurna sehingga `a` dan `b` dapat diperoleh. Faktor RSA adalah:

```text
p = G*a + 1
q = G*b + 1
```

Verifikasi akhir:

```text
p*q = N
```

## 9. Reproduksi

Solver menggabungkan parsing input, simultaneous modular lattice, recovery digit yang hilang, continued-fraction factorization, dan dekripsi RSA.

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

Untuk instance remote baru, source solver menyediakan mode `GAP_GAP_REMOTE=1`.

## 10. Hasil

Flag terverifikasi dari source:

```text
pwnsec{a037f98cd3e49a5f}
```

Validasi yang dicatat: `p*q=N` dan re-enkripsi plaintext menghasilkan ciphertext `c` yang sama.

## 11. Pembelajaran

Pada Common Prime RSA, memanfaatkan pangkat faktor bersama `g` dapat jauh lebih kuat daripada hanya menggunakan persamaan standar `ed-k*phi(N)=1`. Kombinasi relasi modulo `g`, relasi modulo `g^2`, dan kebocoran MSB/LSB `d` mengubah masalah menjadi small-root lattice. Setelah `d` lengkap, struktur `N-1=2g*h` menyediakan pendekatan rasional yang dapat diselesaikan dengan continued fraction.
