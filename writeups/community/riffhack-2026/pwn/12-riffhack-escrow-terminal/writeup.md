---
ctf: "RIFFHACK 2026"
kategori: "Pwn (Binary Exploitation)"
challenge: "RIFFHACK Escrow Terminal"
flag: "bitctf{{35cr0w_n0735_wr173_th3_ch3ck}}"
teknik: "printf(user_note) dengan blocklist yang cuma menolak %n; leak pointer via %p posisional lalu tulis %hn untuk mengalihkan pointer vault aktif ke vault terpercaya"
sumber: "https://github.com/Abdelkad3r/RIFFHACK/tree/main/12-riffhack-escrow-terminal"
---

# RIFFHACK Escrow Terminal — RIFFHACK 2026 (Pwn)

## Deskripsi Singkat

Terminal escrow menu-driven yang dikirim sebagai binary Mach-O ARM64. Kerentanannya adalah `printf(user_note)` di jalur review dengan blocklist yang cuma menolak `%n` polos. Rantai yang dimaksud: leak pointer vault-aktif via `%p` posisional, character count terkontrol-lebar via `%*$c`, dan tulis `%hn` atas count itu ke 16 bit rendah pointer vault-aktif global untuk mengalihkannya ke vault "dispute escrow snapshot" yang sudah disiapkan, yang sudah punya approval latch (`0x51ff`) dan mirror checksum yang benar.

## Analisis

**Langkah 1 — Triase binary.** `file` melaporkan Mach-O 64-bit ARM64. Eksekusi lokal langsung gagal di x86_64 (mismatch tipe CPU), jadi servis remote jadi oracle utama. Binary-nya punya rutin payout tersembunyi yang membuka `/flag.txt`, dan mensyaratkan vault yang sedang aktif punya dua field terpercaya: approval latch `0x51ff` dan field mirror/checksum yang cocok dengan vault aktif.

**Langkah 2 — Temukan bug format-string-nya.** Menu opsi 3 (review catatan buyer tersimpan) memanggil `printf(note, ...)` langsung. Program mencoba memfilter format string berbahaya, tapi blocklist-nya cuma menolak `%n` polos. Write dengan length-modifier seperti `%3$hn` lolos. Fungsi review-nya melewatkan pointer berguna sebagai argumen printf; specifier posisional mengungkapkan apa argumen-argumen itu. Salah satunya menunjuk ke pointer vault-aktif global; argumen berikutnya membocorkan pointer heap di sekitar vault aktif.

**Langkah 3 — Siapkan vault kedua yang terpercaya.** Menu opsi 4 mensinkronkan cache dispute. Program menginisialisasi vault kedua, "dispute escrow snapshot," dengan approval latch dan mirror checksum yang dibutuhkan — keduanya sudah benar; satu-satunya yang menghalangi opsi 5 membayar adalah pointer vault-aktif global-nya masih menunjuk vault pertama yang tidak terpercaya. Mengalihkan pointer itu ke vault kedua adalah seluruh eksploitnya.

**Langkah 4 — Bocorkan base vault-aktif.** Simpan catatan buyer yang men-dump nilai pointer posisional: `%3$p %4$p ... %14$p`. Review catatannya. Satu run tipikal membocorkan `0x557376249d87` sebagai `active+7`; kurangi offset-nya untuk memulihkan base vault-aktif di `0x557376249d80`. Vault kedua duduk di `active + 0x28`, jadi nilai tulis targetnya: `(active + 0x28) & 0xffff`.

**Langkah 5 — Tulis dengan %hn.** Simpan catatan buyer kedua: `%2$*1$c%3$hn`. `%2$*1$c` mencetak persis character count yang dikontrol argumen posisional 1 (lebar tampilan). `%3$hn` menulis count itu sebagai halfword 16-bit ke pointer vault-aktif global. Dipilih sehingga count-nya sama dengan 16 bit rendah target.

**Langkah 6 — Konfirmasi dan finalisasi.** Menu opsi 1 (lihat deal pending) sekarang menampilkan label aktif sebagai "dispute escrow snapshot" alih-alih nama vault asli — mengonfirmasi write-nya kena. Menu opsi 5 (finalize) mengecek latch dan checksum vault aktif. Keduanya cocok. Rutin payout membuka `/flag.txt`.

## Eksploitasi / Solusi

```bash
python3 exploit.py 107.170.63.55 1337
```

Solver yang disertakan mengotomasi seluruh rantai: sinkronkan cache dispute, pasang format string leak, turunkan halfword target, pasang format string write, konfirmasi perubahan vault aktif, dan finalisasi escrow-nya.

```
bitctf{{35cr0w_n0735_wr173_th3_ch3ck}}
```

## Catatan / Insight

Akar masalahnya sama seperti setiap bug format-string: renderer catatan memperlakukan teks yang dikontrol user sebagai format string. Blocklist `%n` adalah strategi yang ditakdirkan gagal karena argumen posisional, width specifier, dan length modifier memberi attacker banyak cara setara untuk mengekspresikan read dan write. `printf("%s", note)` adalah perbaikannya; `fputs(note, stdout)` versi yang lebih aman. Pelajaran keduanya soal desain pengecekan: mengandalkan state heap yang bersebelahan untuk memilih objek "terpercaya" itu rapuh karena satu pointer overwrite saja membalik keputusan trust-nya.

## Flag

```
bitctf{{35cr0w_n0735_wr173_th3_ch3ck}}
```
