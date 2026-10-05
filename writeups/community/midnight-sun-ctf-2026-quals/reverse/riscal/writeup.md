---
ctf: "Midnight Sun CTF 2026 Quals"
kategori: "Reverse Engineering"
challenge: "riscal"
flag: "midnight{RISCV_1S_4_34zy_1S4_70_unDeRst4Nd!!}"
teknik: "ELF RISC-V 64-bit yang memvalidasi input terhadap string hardcoded di .rodata; cukup diselesaikan dengan strings | grep"
sumber: "https://github.com/Abdelkad3r/midnight-sun-ctf-2026-quals/tree/main/riscal"
---

# riscal — Midnight Sun CTF 2026 Quals (Reverse Engineering)

**Info soal:** Trivial, target RISC-V 64-bit Linux.

## Deskripsi Singkat

Nama "riscal" adalah plesetan dari RISC-V + "rascal" (bandel). Soalnya sebuah ELF RISC-V 64-bit tunggal yang menerima input user dan memvalidasinya sebagai flag.

Label kategorinya — *"reverse engineering"* + *"RISC-V"* — membuat kita berpikir harus menyiapkan cross-disassembler, menjalankan binary statis lewat `qemu-user`, mempelajari calling convention RV64, dan mulai menganotasi hasil decompile secara manual. Padahal solusi yang dimaksud jauh lebih sederhana: `strings`.

## Recon

Perintah recon paling pertama pada soal reverse engineering apa pun adalah `strings | grep` untuk format flag. Cuma butuh 50 milidetik dan langsung menyingkirkan kemungkinan "flag-nya cuma nongkrong di `.rodata`" sebelum menghabiskan waktu untuk analisis yang lebih serius.

```bash
$ file riscal
riscal: ELF 64-bit LSB executable, UCB RISC-V, version 1 (SYSV), dynamically linked, ...

$ strings riscal | grep midnight
midnight{RISCV_1S_4_34zy_1S4_70_unDeRst4Nd!!}
```

Itu flagnya. Submit dan soal selesai.

## Analisis

`objdump -d` singkat mengonfirmasi kenapa ini berhasil: binary-nya cuma melakukan `strcmp` terhadap string `.rodata` yang hardcoded. Tidak ada XOR, tidak ada packing, tidak ada obfuskasi, tidak ada dekripsi runtime. Flag-nya adalah target literal dari perbandingan tersebut.

## Eksploitasi / Solusi

Sudah selesai di tahap recon — tidak perlu langkah tambahan apa pun.

## Catatan / Insight

Isi flag-nya sendiri — *"RISC-V is a easy ISA to understand"* — adalah petunjuk bahwa soal ini memang dirancang untuk mudah didekati. Framing kategorinya-lah yang jadi pengalih perhatian.

**Pelajaran:**

1. **`strings | grep <format_flag>` adalah langkah recon literal pertama di setiap soal RE.** Ini adalah perintah *pertama*, bukan yang terakhir. Kebanyakan soal rev "mudah" selesai dengan cara ini, dan bahkan soal yang benar-benar sulit pun seringkali punya petunjuk parsial dalam bentuk plaintext.
2. **Jangan biarkan label arsitektur menentukan seberapa besar usahamu.** "RISC-V" terdengar menakutkan, tapi instruction set yang asing hanya relevan kalau kamu harus benar-benar *memahami* jalur kodenya. Kalau flagnya cuma string statis, arsitekturnya tidak relevan sama sekali — parser ELF tetap bisa menemukannya.
3. **Label kategori CTF adalah bingkai, bukan kontrak.** Soal yang diarsipkan di "reverse engineering" bisa saja selesai dengan `strings`. Soal di "stego" bisa saja selesai dengan hex editor. Terlalu fokus mencocokkan teknik dengan ekspektasi kategori justru menghalangi langkah paling sederhana: membaca inputnya langsung.
4. **Tool sering bekerja lintas-arsitektur lebih baik dari yang dikira.** `strings`, `file`, `readelf`, `objdump -d`, dan `binwalk` semuanya menangani RISC-V (dan ARM, MIPS, PowerPC) dengan baik. Jangan langsung ambil toolchain khusus sebelum toolchain dasar terbukti tidak berguna.

## Flag

```
midnight{RISCV_1S_4_34zy_1S4_70_unDeRst4Nd!!}
```
