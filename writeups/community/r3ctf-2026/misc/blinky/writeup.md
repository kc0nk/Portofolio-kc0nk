---
ctf: "R3CTF 2026 (r3kapig)"
kategori: "Misc (Hardware/RTL)"
challenge: "Blinky"
flag: "r3ctf{seCur3_aNaIy2Ing_p3rFOrmanc3_wOrkflOw4124}"
teknik: "PAC gate MIPS64r6 dibobol lewat Spectre-style speculative PAC-gated data-load — bad tag membatalkan fault di jalur salah-prediksi, good tag meninggalkan jejak cache; tanpa pernah men-commit satu fault pun"
sumber: "https://github.com/Abdelkad3r/R3CTF-2026/tree/master/misc/blinky"
---

# Blinky — R3CTF 2026 (Misc / Hardware)

## Deskripsi Singkat

Model RTL lengkap dari SoC MIPS64r6. Kernel mengekspos `print_flag` di `0x2030`. Kode user dimuat di `0x0`, harus tetap di bawah `0x2000`. Jump kernel langsung diblokir oleh pointer authentication; satu PAC fault yang ter-commit mengunci gate untuk sisa run, jadi brute-force arsitektural atas 256 kemungkinan tag 8-bit tidak bisa dipakai.

## Analisis

**Langkah 1 — Baca PAC gate-nya.** `core_branch.sv` menggerbangi `jr` user-ke-kernel: silang yang ter-commit dengan tag salah memicu PAC fault. `cp0.sv` menghitungnya, dan `PAC_FAULT_LIMIT = 1` di build ini — jadi satu tebakan salah yang "berisik" mengunci kita permanen.

**Langkah 2 — Temukan side channel di data-load yang digerbangi-PAC.** `core_EX.sv` punya jalur load terpisah yang digerbangi PAC: tag baik → load lanjut ke `PAC_PROBE_ADDR`; tag salah → NO_LOAD + PAC fault yang ditunda. Yang penting: instruksi speculative yang di-squash tidak men-commit exception. Jadi di jalur salah, load tag-salah membatalkan PAC fault-nya, sementara load tag-baik menyentuh `PAC_PROBE_ADDR` (`0x1000` di build ini) dan meninggalkan jejak cache. Waktu-kan load normal dari `0x1000` sesudahnya untuk membedakan hit dari miss.

**Langkah 3 — Latih misprediksi yang aman.** BHT mengindeks pada bit PC. Dua branch yang PC-nya berbagi indeks 6-bit yang sama akan alias di predictor. Melatih branch oracle itu sendiri sebagai not-taken tidak aman karena fall-through-nya *adalah* load yang digerbangi-PAC dan akan tereksekusi secara arsitektural. Jadi exploit-nya menempatkan branch training yang aman di `0x40` dan branch oracle sungguhan di `0x140`; keduanya kena indeks BHT yang sama (`0x10`).

**Langkah 4 — Timing probe-nya.** Sebelum setiap percobaan, invalidasi kedua D-cache way untuk probe set. Latih alias-nya empat kali, eksekusi branch oracle sekali, lalu timing load normal dari `0x1000`. Kalibrasi lokal: tag salah → ~5 cycle, tag baik → ~2 cycle. Threshold `sltiu $t3, $v0, 4`. Konfirmasi dengan probe kedua untuk menolak sampel yang bising.

**Langkah 5 — Iterasi 256 tag dan lompat.** Loop 256 tag, invalidasi probe set, latih branch alias sebagai not-taken, eksekusi branch oracle yang mispredict, timing load dari `0x1000` — tanpa pernah men-commit satu PAC fault pun di sepanjang loop. Setelah tag yang benar terkonfirmasi, `jr` yang terautentikasi berjalan bersih, kernel mode dimasuki, `print_flag` berjalan.

## Eksploitasi / Solusi

```bash
$ curl --data-binary @exploit.mem http://challenge.ctf2026.r3kapig.com:32619/submit
r3ctf{seCur3_aNaIy2Ing_p3rFOrmanc3_wOrkflOw4124}
HALT
```

## Catatan / Insight

Flag `seCur3_aNaIy2Ing_p3rFOrmanc3_wOrkflOw4124` (dengan `4124` terbaca sebagai "tahun kelahiran Alan Turing"-nya versi lelucon) adalah rujukan jelas ke serangan kelas Spectre: workflow aman apa pun yang mengautentikasi di jalur arsitektural tapi membiarkan eksekusi spekulatif tak terperiksa membocorkan token autentikasi lewat state mikroarsitektural. Di silikon produksi ini persis bentuk Spectre v1/v2/v4, Meltdown, dan keluarga LVI. Mitigasi di hardware asli adalah menyerialisasi jendela spekulatif (`csdb`, `lfence`), menandai cache line yang tersentuh spekulatif secara terpisah, atau menggerbangi efek samping yang teramati pada saat commit.

## Flag

```
r3ctf{seCur3_aNaIy2Ing_p3rFOrmanc3_wOrkflOw4124}
```
