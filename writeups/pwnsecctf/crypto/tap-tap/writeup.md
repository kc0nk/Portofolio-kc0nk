# tap tap

> **Event:** PwnSec CTF 2026  
> **Kategori:** Crypto  
> **Status:** Solved  
> **Flag format:** `pwnsec{...}`

## 1. Gambaran Umum

Challenge membocorkan 80 bit teratas dari 180 state berturut-turut pada recurrence Fibonacci orde 25 di atas field dengan modulus prima 128-bit. Modulus sangat dekat dengan `2^128`, sehingga relasi annihilating yang pendek tetap dapat terlihat sebagai vector pendek pada lattice meskipun 48 bit bawah setiap state hilang.

Tahapan utama adalah:

```text
recover modulus p
    ↓
recover tap C
    ↓
recover 48-bit low parts state awal
    ↓
rekonstruksi seluruh state
    ↓
regenerasi SHA-256 + SHAKE-256
    ↓
flag
```

## 2. Pembangkitan State

Modulus dipilih dalam bentuk:

```text
p = 2^128 - d
2^48 <= d <= 2^50
```

Terdapat 25 tap acak `C[0..24]` dan 25 state awal `A[0..24]`. Recurrence-nya:

```text
A[i+25] = sum(C[j] * A[i+j] for j=0..24) mod p
```

Yang dipublikasikan hanyalah:

```text
Y_i = A[25+i] >> 48
```

Jadi setiap state dapat ditulis:

```text
A_i = 2^48*Y_i + Z_i
0 <= Z_i < 2^48
```

## 3. Annihilating Polynomial

Untuk vector annihilating pendek berukuran 90, kombinasi linear terhadap `Y` pada beberapa sliding window tetap memiliki struktur modular. Karena modulus berbeda dari `2^128` hanya sebesar `2^48..2^50`, residual akibat modulus dapat diseimbangkan dengan koordinat koefisien. Implementasi menggunakan scaling 64 agar batas koordinat seimbang.

Basis lattice berdimensi 180 direduksi dengan **BKZ-35**. Hasilnya mengekspos beberapa polinomial annihilating independen berderajat 89.

## 4. Recovery Modulus

Resultant dari dua polinomial annihilating tersebut mengandung faktor `p^25`, karena orde recurrence minimal adalah 25. GCD dari beberapa resultant independen menghasilkan modulus:

```text
p = 340282366920938463463374127620052448857
2^128 - p = 479811715762599
```

Setelah polinomial direduksi di `F_p[x]`, GCD menghasilkan characteristic polynomial berderajat 25. Koefisien derajat 0 sampai 24 kemudian dinegasikan untuk memperoleh tap `C`.

## 5. Recovery Low Bits State

Setelah tap diketahui, setiap state berikutnya merupakan kombinasi linear dari 25 state pertama. Low part ditengahkan dengan:

```text
Z_i = W_i + 2^47
```

Persamaan kemudian dapat ditulis dalam bentuk:

```text
q_j W - t_j = W_j (mod p)
```

Semua unknown dan residual memiliki magnitude di bawah `2^47`. Lima puluh persamaan state berikutnya digunakan untuk membangun lattice BDD berdimensi 75:

```text
[ I_25   Q ]
[  0    pI_50 ]
```

LLL diikuti Babai nearest-plane memulihkan 25 low parts state awal.

## 6. Verifikasi Recurrence

State yang telah lengkap diregenerasi menggunakan recurrence yang sama. Seluruh 180 output high bits harus cocok dengan nilai publik. Source solver mencatat bahwa semua output cocok, sehingga false positive dari lattice dapat disingkirkan.

Untuk memperoleh state sebelumnya, solver menggunakan invers `C[0]` modulo `p` dan melakukan langkah mundur sebanyak 25 kali sehingga sequence asli `A[0..204]` dapat direkonstruksi.

## 7. Dekripsi

Kunci dibentuk dari concatenation base-10 seluruh 205 state, kemudian di-hash menggunakan SHA-256 dan diperluas dengan SHAKE-256 sesuai `chall.py`. Setelah seluruh state direkonstruksi, proses ini dapat diulang secara deterministik untuk mendapatkan kunci dan membuka ciphertext.

## 8. Reproduksi

Solver resmi sudah memuat modulus dan tap yang telah dipulihkan, membaca `Y` serta ciphertext dari challenge, membangun state lattice, menjalankan LLL/Babai, memverifikasi seluruh output, lalu melakukan dekripsi.

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

## 9. Hasil

Flag terverifikasi:

```text
pwnsec{wR17in6_17_t0oK_m3_thRe3__d4y5_d1d_4I_50lv3_i7_1n_thRe3_53c0nDs??}
```

## 10. Pembelajaran

Generator Fibonacci terpotong dengan modulus yang dekat ke pangkat dua tetap dapat diserang karena annihilating relation menghasilkan vector pendek. Scaling koordinat penting agar lattice mencerminkan bound aktual `2^128-p`. Setelah modulus dan tap ditemukan, recovery state menjadi BDD/CVP dengan jarak yang cukup jelas antara solusi dan kandidat lain.
