---
ctf: "ASIS CTF Quals 2026"
kategori: "Misc"
challenge: "Mic Check"
flag: "ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}"
teknik: "Decoder font seven-segment ASCII custom; baris top-segment yang melenceng 1-2 kolom diatasi dengan memperlakukannya sebagai hitungan (count), bukan posisi"
---

# Mic Check — ASIS CTF Quals 2026 (Misc, Baby)

## Deskripsi Singkat

Handout-nya satu file berisi lima blok ASCII tiga-baris, masing-masing menggambar sebuah kata leetspeak dalam font seven-segment gambar-tangan. Prompt-nya menjanjikan "hanya mata manusia yang baik hati yang masih bisa men-decode layar LED vintage ini" — dan secara visual kamu memang bisa membaca kelima blok dalam waktu sekitar satu menit: `farewell`, `classic`, `hello`, `uncertain`, `era!`.

Jebakannya, dan alasan warm-up ini menghargai decoder yang tepat alih-alih Ctrl-F ke Google: seninya **spasinya proporsional** dan **baris top-segment-nya melenceng 1-2 kolom di tiga dari lima blok**. Decoder yang mempercayai posisi pixel tiap `_` menghasilkan `cl9ss1l` untuk blok 2 dan `unc3rt4n1` untuk blok 4 — tidak satu pun kata.

## Analisis

Tiga baris per blok adalah petunjuk visualnya: digit seven-segment butuh tepat tiga baris teks untuk digambar — satu untuk segmen atas, satu untuk vertikal atas plus bar tengah, satu untuk vertikal bawah plus bar bawah.

**Langkah 1 — Bangun font dari seninya sendiri, bukan impor font standar.** Pembuat challenge rutin menambahkan glyph (`r`, `w`, `t`, `!` di sini) yang tidak bisa dirender seven-segment display sungguhan mana pun.

**Langkah 2 — Segmentasi berdasarkan baris yang bisa dipercaya.** Dua baris bawah membawa vertikal dan self-aligning; baris atas cuma satu karakter jarang per glyph dan persis tempat kerusakan whitespace bersembunyi — di copy-paste, di renderer terminal, di seni aslinya sendiri.

**Langkah 3 — Ubah sinyal posisional jadi sinyal hitungan saat posisi tidak bisa diandalkan.** Jumlah segmen atas bertahan terhadap drift horizontal apa pun. Hanya tiga pasang glyph di font ini yang berbeda semata di segmen atas (`4`/`9`, `l`/`c`, `u`/`0`) — glyph lainnya sepenuhnya ditentukan dua baris bawahnya, yang pixel-accurate di challenge ini. Enumerasikan ruang pencarian pasangan-kembar yang kecil, pertahankan hanya assignment yang total segmen-atasnya cocok dengan jumlah underscore, de-leet hasilnya, dan cross-check terhadap wordlist.

**Langkah 4 — Paksa "tepat satu bacaan per blok".** Solver-nya membatalkan proses kalau blok mana pun ambigu, jadi outputnya adalah bukti, bukan preferensi.

## Eksploitasi / Solusi

```
$ python3 solution/solve.py
  [1]  f4r3w3ll    farewell
  [2]  cl4ss1c     classic
  [3]  h3ll0       hello
  [4]  unc3rt41n   uncertain
  [5]  3r4!        era

  ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
```

**Kenapa bacaan ini yang benar:** dua pengecekan independen sepakat pada lima kata yang sama. **Struktural**: setiap blok punya tepat satu tiling dari dua baris bawah yang memakai setiap kolom ber-tinta dan menghasilkan glyph dari font-nya; setiap assignment top-segment yang ambigu punya tepat satu setting yang cocok dengan jumlah underscore di baris atas dan ter-de-leet jadi kata Inggris. **Semantik**: menggabungkan plaintext-nya terbaca *"farewell classic, hello uncertain era!"* — penegasan ulang flavour text challenge-nya sendiri.

## Catatan / Insight

- **Seni ASCII tiga-baris hampir selalu seven-segment display.** Bangun font-nya dari seninya sendiri, bukan impor font.
- **Segmentasi pada baris yang bisa dipercaya.** Baris bawah self-aligning; baris atas-lah yang rentan kerusakan whitespace.
- **Ubah sinyal posisional jadi sinyal hitungan saat posisi tidak diandalkan.** Jumlah segmen bertahan terhadap drift horizontal apa pun.
- **Biarkan plaintext yang memutuskan.** Dengan pemetaan leetspeak dan wordlist, ruang pencarian encoding warm-up runtuh jadi satu bacaan tunggal. Kalau hasil decode bukan kata, yang salah decode-nya — bukan wordlist-nya.

**Pelajaran lintas-kategori:** disiplin yang sama berlaku di mana pun data di wire tidak sepakat dengan data saat dirender — kanonikalisasi header HTTP di Web, evidence hasil copy-paste yang kehilangan whitespace di Forensics, encoding ASCII berbasis-font (Base65536, Base2048, stego whitespace) di Reversing. Decoder yang beroperasi pada struktur abstrak (hitungan token, adjacency token) alih-alih posisi pixel tahan terhadap kerusakan tampilan.

## Flag

```
ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
```
