---
ctf: "ASIS CTF Quals 2026"
kategori: "Reverse Engineering"
challenge: "ASIS Arch"
flag: "ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}"
teknik: "VM 16-bit custom; ISA dipulihkan dari relokasi R_X86_64_RELATIVE; instruksi terenkripsi dengan keystream per-alamat; transform cipher branch-free 660-langkah dibalik secara simbolik tanpa brute force"
sumber: "https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Reverse/ASISArch"
---

# ASIS Arch — ASIS CTF Quals 2026 (Reverse Engineering, Medium)

## Deskripsi Singkat

Handout-nya ELF Linux 14 KB (`qemu-asisarch`) plus ROM 32 KB (`challenge.rom`). QEMU sungguhan berukuran megabyte; binary ini kilobyte. `.text` 2549 byte adalah **seluruh CPU**-nya, dan `.data.rel.ro` 2 KB adalah tabel dispatch opcode berbentuk 256×8 — bentuk klasik interpreter dispatch.

## Analisis

**Container ROM.** Header 32-byte memvalidasi sebelum body disalin ke alamat guest 0. Entry PC tidak disimpan langsung — dibangun dengan menukar nibble tiap byte header lalu merotasi word hasilnya. Scramble nibble yang sama ini men-decode **setiap** immediate instruksi — "middle-endian nibbles" yang disebut di nama flag.

**Fetch stage — instruksi terenkripsi dengan alamatnya sendiri.** Ini inti challenge-nya. Setiap instruksi 4 byte, tapi sebelum di-decode, fetch stage menurunkan keystream per-alamat: `raw = ((PC ^ 0x9e37) * 0x1039 + 0x79b9) & 0xffff`, lalu `sel` memilih satu dari empat permutasi byte dan `k` adalah keystream word. Tiga konsekuensi: **byte yang sama ter-decode berbeda di alamat berbeda** (sweep linier menghasilkan instruksi yang terlihat plausibel tapi salah, dan tidak pernah tersinkronisasi ulang); **ROM tidak bisa di-relokasi** (kode menempel ke alamat tempat ia dirakit); **nomor register dipermutasi dua kali**. Operand register kedua instruksi ALU/memori tidak ada di byte instruksi sama sekali — dikemas di 3 bit rendah immediate lewat permutasi yang sama, dengan 13 bit sisanya dipakai sebagai displacement alamat.

**Memulihkan opcode map tanpa menebak.** `.data.rel.ro` menyimpan tabel dispatch 256-entri, tapi di PIE ia nol-diisi di disk dan diisi saat load-time oleh relokasi `R_X86_64_RELATIVE`. **Membaca tabel relokasi langsung memberi mapping-nya** — 26 opcode hidup, 230 entri null yang trap sebagai "illegal instruction". Dua hal menarik: aritmetika ditulis dengan identitas carry-free (`add`/`sub` tidak terlihat seperti penjumlahan sekilas pandang), dan `sbox` adalah instruksi substitusi tanpa padanan di CPU sungguhan mana pun — petunjuk pertama bahwa ROM-nya sedang mengerjakan block cipher.

**Reimplementasi mesinnya — validasi di cycle count.** `asisarch.py` mereimplementasi mesin dalam ~200 baris. Validasi yang penting bukan "menghasilkan output" tapi **cocok dengan binary asli di cycle count**, baik jalur accept maupun reject — mencocokkan teks saja cuma membuktikan jalur I/O.

**Disassembly ROM (recursive descent).** Sweep linier tidak berguna — fetch stage re-key per PC. `disasm.py` adalah disassembler recursive-descent: mulai dari entry PC header, ikuti `jmp`/`jz`/`jnz`/`call`, berhenti di `ret`/`halt`. 7960 instruksi tercapai, mengungkap panjang flag persis **44 byte** (22 word 16-bit), dibuffer di `0xc000`.

**Rutin verifikasi.** Antara pengecekan panjang dan perbandingan ada satu basic block raksasa — `0x0024` sampai `0x7873`, **sepenuhnya unrolled, tanpa cabang**. Mengangkatnya menunjukkan persis **660 store ke buffer**, dalam tiga bentuk berulang, 220 masing-masing — sepuluh ronde dari tiga pass di atas 22 word: **Substitute** (`w[i] = S16(w[i]) XOR K[round][i]`), **Diffuse forward** (`w[i] = w[i] + w[i-1] + 0x5a5a`), **Diffuse backward** (`w[i] ^= sigma(w[i+1]) XOR rol(sigma(w[i+2]), r)`). Setelah dua ronde, setiap word output bergantung pada setiap byte input — menebak flag sebagian-sebagian mustahil.

## Eksploitasi / Solusi — Membalik Transform-nya

Observasi kuncinya: **transform-nya tidak punya cabang**, jadi urutan update buffer identik tak peduli input apa pun. Itu memungkinkan mengangkatnya sekali, secara simbolik, jadi daftar langkah elementer. `solve.py` menelusuri block itu sekali, melacak ekspresi simbolik per register alih-alih nilai. Hasilnya: 660 langkah berbentuk `buf[i] <- f(buf[i], word lain, konstanta)`. Dua properti membuatnya trivial dibalik: setiap langkah menyebut target-nya sendiri **tepat sekali**, dan word lain yang dibaca suatu langkah tidak dimodifikasi oleh langkah itu sendiri. Membalikkan jadi mekanis: urungkan `xor` dengan `xor`, `add` dengan pengurangan, `rol` dengan `ror`, `sbox` dengan permutasi invers. Mulai dari 22 word yang diharapkan dan jalankan langkah mundur langsung memulihkan input — **tanpa brute force, tanpa SMT solver**.

```
$ python3 solution/solve.py
[+] lifted 660 elementary buffer updates
[+] flag: ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
[+] emulator says: ACCEPTED (8906 cycles)
```

Dikonfirmasi terhadap binary asli (bukan cuma reimplementasi): `[+] Access Granted! Flag verified.`

## Catatan / Insight

- **Ukuran adalah petunjuk pertama.** `.text` 2.5 KB dengan tabel pointer 2 KB di `.data.rel.ro` adalah interpreter, dan tabel dispatch-nya adalah ISA-nya. Jangan mulai dengan membaca handler — mulai dengan menghitungnya.
- **Pulihkan tabel dari relokasi, bukan debugger.** Di PIE, tabel function pointer hidup di `.rela.dyn`. Parsing-nya memberi opcode map secara statis, tanpa eksekusi dan tanpa tebakan.
- **Validasi VM hasil reimplementasi di cycle count, bukan output.** Mencocokkan teks hanya membuktikan jalur I/O.
- **Obfuskasi branch-free mengalahkan dirinya sendiri.** Unrolling transform menyembunyikan strukturnya dari pembaca, tapi juga menghilangkan setiap keputusan yang bergantung-input — persis yang memungkinkan urutan operasinya diangkat sekali dan dibalik dalam bentuk tertutup. Satu cabang data-dependent saja di block itu akan memaksa solver.

## Flag

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```
