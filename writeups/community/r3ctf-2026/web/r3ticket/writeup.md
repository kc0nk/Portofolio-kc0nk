---
ctf: "R3CTF 2026 (r3kapig)"
kategori: "Web (Python)"
challenge: "r3ticket"
flag: "r3ctf{H0pE_y0u_1ovE-THIS_tICKet-SErlEs-XD58c5c}"
teknik: "Helper Lagrange interpolation get_num(nums, index) dievaluasi di index negatif besar; decode base-K balanced-remainder memberi 128 persamaan linier dari satu query oracle"
---

# r3ticket — R3CTF 2026 (Web / Python)

## Deskripsi Singkat

Server membangkitkan 128 integer rahasia 16-bit. Ia mengekspos satu query ke helper `get_num(nums, index)`, lalu menjalankan 16 ronde ber-timer di mana setiap ronde mencetak 64 digit desimal pertama dari `sum(num**x for num in nums)` dan menuntut eksponen 24-bit `x` dalam tiga detik. Pitch yang dimaksud: "kamu dapat satu pertanyaan oracle, lalu kamu butuh keajaiban." Kenyataannya, `get_num` di index negatif besar jauh lebih powerful dari oracle biasa.

## Analisis

**Langkah 1 — Kenali basis Lagrange-nya.**

```python
def get_num(nums, index):
    if index > len(nums) - 1:
        return 0
    result = 0
    for i in range(len(nums)):
        part = 1
        for j in range(len(nums)):
            if j == i: continue
            part *= (index - j) // (i - j)
        result += part * nums[i]
    return result
```

Ini adalah basis interpolasi Lagrange: untuk `index` integer di `[0, 127]`, `part` memilih `nums[index]` dan segalanya lain nol. Blok `index > 127` memotong sisi positif, tapi index negatif lolos bebas. Untuk `index = -K`: `get_num(nums, -K) = sum_i L_i(-K) · nums[i]`, di mana `L_i(-K)` adalah fungsi rasional yang diketahui dari `K`.

**Langkah 2 — Hilangkan penyebut dengan 127!.** Penyebut `L_i` adalah `i! · (127-i)!`, dan setiap pembagi semacam itu membagi `D = 127!`. Jadi `D · L_i(-K)` adalah polinomial integer dalam `K`. `D · get_num(nums, -K) = C_0 + C_1·K + … + C_127·K^127`, dan setiap koefisien `C_k` adalah kombinasi *linier* dari 128 nilai `nums[i]` yang tidak diketahui, dengan koefisiennya sendiri sudah diketahui (didapat dari mengekspansi basis Lagrange dalam `K`).

**Langkah 3 — Pilih K cukup besar untuk decoding base-K.** Decode base-K `q, r = divmod(y, K)` memulihkan digit `C_0 = r` hanya kalau `|C_0| < K/2`. Agar seluruh polinomial ter-unpack bersih (dengan remainder seimbang untuk koefisien bertanda), `K` harus melebihi `|C_k|` terbesar yang mungkin — sekitar 350 digit desimal untuk 128 nilai 16-bit tidak diketahui.

**Langkah 4 — Decode balanced-remainder.** Query `-K`, kalikan respons dengan `D`, ekstrak 128 remainder seimbang. Hasilnya: 128 persamaan linier `C_k = sum_i A[k][i] · nums[i]` dalam 128 hal yang tidak diketahui.

**Langkah 5 — Selesaikan dengan trik nullspace kecil.** Matriks `A` 128×128 punya rank 127 mod 1000003 (prima yang cocok untuk challenge ini), jadi ada ruang solusi 1-D. Tapi setiap `nums[i]` adalah nilai 16-bit di `[0, 65535]`. Enumerasikan satu koordinat dari 0 sampai 65535 sepanjang garis nullspace dan pertahankan titik unik di mana semua 128 koordinat muat di 16 bit. Itu memulihkan seluruh 128 rahasia dari satu query oracle.

**Langkah 6 — Log-sum-exp scan untuk eksponen tiap ronde.** Begitu `nums` diketahui, setiap ronde meminta kita membalik `prefix = first_64_digits(sum(num_i^x))` untuk `x` 24-bit. Menghitung setiap sum untuk setiap `x` terlalu lambat dan memakan ukuran integer raksasa. Kerjakan dalam logaritma desimal: `H(x) = sum_i num_i^x`, `log10(H(x))` menentukan digit terdepan. `scan_exp.cpp` men-scan seluruh 2^24 eksponen dengan filter awal memakai rahasia terbesar yang sudah dipulihkan, lalu log-sum-exp stabil untuk tiap kandidat. Cocokkan terhadap mantissa target 64-digit; setiap ronde menghasilkan satu kandidat unik dalam toleransi `1e-8`, selesai jauh di dalam batas waktu 3 detik.

## Eksploitasi / Solusi

```
You won! Here is your real ticket: r3ctf{H0pE_y0u_1ovE-THIS_tICKet-SErlEs-XD58c5c}
```

## Catatan / Insight

Trik r3ticket adalah versi-basis-Lagrange dari pola yang sama yang muncul di serangan klasik polynomial-secret-sharing: evaluasi mana pun dari sebuah polinomial di nilai di luar domain yang dimaksud membocorkan kombinasi linier dari koefisiennya, dan cukup banyak evaluasi di titik-titik yang dipilih cerdas merekonstruksinya. Di sini satu *evaluasi tunggal* di satu titik raksasa saja sudah cukup karena decoding base-K mengubah satu integer besar jadi 128 integer kecil secara gratis.

## Flag

```
r3ctf{H0pE_y0u_1ovE-THIS_tICKet-SErlEs-XD58c5c}
```
