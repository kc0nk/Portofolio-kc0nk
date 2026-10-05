---
ctf: "scriptCTF 2026"
kategori: "Reverse Engineering"
challenge: "F**K"
flag: "scriptCTF{t1mm1ng_s1d$_ch@nn31}"
teknik: "Program Brainfuck 28.786-byte; 31 pengecekan byte aljabar (input += C; temp = A*K+B; input -= temp) tersembunyi di balik noise visual; flag hidup di jumlah iterasi loop [-], bukan di output"
sumber: "https://github.com/Abdelkad3r/scriptCTF-2026/tree/main/reverse/funk"
---

# F\*\*K — scriptCTF 2026 (Reverse Engineering, 454 poin)

## Deskripsi Singkat

Handout-nya satu file bernama `funk` — tanpa header ELF, tanpa shebang, seberat 28.786 byte. Judul yang disensor dan aturan "tidak boleh mengumpat" adalah dua petunjuk pertama: bahasanya cuma pakai delapan karakter punctuation ASCII, dan leluconnya baru terasa kalau file-nya memang Brainfuck.

## Analisis

**Identifikasi bahasanya.** Setiap byte non-whitespace termasuk `< > + - . , [ ]` — seluruh instruction set Brainfuck. Hitungan mentahnya sengaja mengintimidasi: 8.376 `+`, 5.273 `-`, 7.461 `>`, 7.376 `<`, 126/126 `[`/`]` (seimbang sempurna), hanya 9 instruksi output vs 38 instruksi input. Dua sifat struktural langsung membubarkan intimidasinya: bracket-nya seimbang sempurna dan nesting-nya cuma **dua level dalam** — tidak ada control flow arbitrary.

**Tentukan panjang input.** VM Brainfuck kecil terinstrumentasi mengonfirmasi hanya 31 dari 38 instruksi `,` yang benar-benar tereksekusi; 7 sisanya duduk di dalam loop umpan mati yang control cell-nya sudah nol saat loop dicapai. 31 pembacaan hidup menulis berurutan ke cell `0..30` — cocok persis dengan format flag scriptCTF: `scriptCTF{` 10 byte, `}` satu, menyisakan body 20-byte — 31 byte total.

**Lipat noise visualnya.** Sebagian besar 28 KB-nya redundan secara aljabar. Aritmetika berurutan runtuh modulo 256 (`+++-+---++- → satu net ADD/SUB`), pergerakan pointer runtuh sama (`>>>>><<<<< → tanpa pergerakan`). Setelah dilipat, hanya **395 operasi top-level** tersisa. Setiap pengecekan byte bermakna memakai template dua-idiom yang sama:

- **Idiom 1 — kalikan-dan-transfer:** `A [ - < K > ]` — cell kiri bertambah `A * K`.
- **Idiom 2 — kurangi-ke-input:** menguras temporary ke cell input jauh sebagai pengurangan.

**Pulihkan satu target byte.** Setiap pengecekan byte tereduksi jadi empat konstanta — `C`, `A`, `K`, `B` — dengan bentuk: `input += C; temporary = A*K+B; input -= temporary`. Residualnya nol persis ketika `expected = (A*K + B - C) mod 256`. Untuk index input 1, konstantanya `C=39, A=8, K=17, B=2`, memberi `expected = 8*17 + 2 - 39 = 99 = 'c'` — byte kedua dari `scriptCTF`. Index 0 serupa: `12*12 + 0 - 29 = 115 = 's'`. `s` dan `c` yang sudah diketahui dari prefix flag mengonfirmasi formula dan konvensi byte-order sebelum byte tidak-diketahui mana pun di-decode.

**Decode seluruh 31 pengecekan yang teracak.** Perbandingannya tidak disusun berurutan input. Men-scan program hasil lipat untuk template perbandingan, mencatat pointer cell-input saat itu, dan mengurutkan berdasarkan pointer itu menghasilkan tabel lengkap 31 entri, menggabungkan byte target:

```
scriptCTF{t1mm1ng_s1d$_ch@nn31}
```

`$` di index 21 dan `@` di index 25 terlihat seperti tebakan pengenalan-glyph tapi sebenarnya nilai byte eksak dari aritmetikanya: index 21 → `2*42+1-49=36='$'`; index 25 → `2*54+1-45=64='@'`. Tanpa ambiguitas, tanpa penyetelan manual.

## Eksploitasi / Solusi

**Kanal timing — di sinilah flag sebenarnya hidup.** Setiap perbandingan diakhiri `[-]`, idiom Brainfuck standar untuk membersihkan cell saat ini dengan mendekrement sampai nol. Dengan cell 8-bit wrapping: `input == target` → residual `0x00` → 0 iterasi clear; `input == target+1` → residual `0x01` → 1 iterasi; `input == target−1` → residual `0xff` → 255 iterasi (wraparound). Program tidak mencetak apa pun saat sukses. Ia berakhir dengan `+[]` — `+` membuat cell saat ini non-nol, `[]` loop selamanya tanpa mengubahnya. **Setiap kandidat input hang.** Yang berbeda adalah *jumlah step instruksi Brainfuck* yang dibutuhkan untuk mencapai sentinel itu — flag-nya terkode sepenuhnya di count itu.

Run VM terinstrumentasi pada flag hasil pemulihan:

```
steps to final +[] sentinel: 462101
+1 mutation timing delta: min=2 max=2
−1 mutation timing delta: min=510 max=510
```

Mengubah satu byte naik satu → 2 step ekstra. Turun satu → 510 step ekstra (255 iterasi × 2 instruksi per iterasi). Kandidat hasil pemulihan adalah **minimum global unik** di seluruh 31 loop residual independen. Hint `t1mm1ng_s1d$_ch@nn31` — sengaja dieja "timing side channel" dalam leetspeak — mengiklankan desainnya sendiri di dalam flag-nya.

```bash
python3 reverse/funk/scripts/solve.py challenge/funk
# flag: scriptCTF{t1mm1ng_s1d$_ch@nn31}
```

## Catatan / Insight

**28 KB Brainfuck bukan 28 KB logika** — itu cuma beberapa ratus operasi logika setelah dilipat secara aljabar, dan masing-masing cocok dengan template empat-konstanta yang sama. Petunjuk sebenarnya: program-nya *tidak punya output*. Checker yang tidak pernah mencetak "benar" tidak sedang membandingkan terhadap string tersimpan; ia pasti membandingkan secara struktural. Begitu template perbandingannya dikenali, men-decode flag-nya cuma satu loop scan atas AST. 454 poinnya menghargai dua langkah — mengenali bahasanya, dan mengenali bahwa kesulitannya adalah *volume*, bukan *kompleksitas*. Kanal timing-nya adalah sentuhan elegan, bukan seranganya: mengetahui bahwa flag-nya adalah tujuan desain itulah yang memberitahu bahwa aljabar yang kamu lihat adalah comparator, bukan komputasi.

## Flag

```
scriptCTF{t1mm1ng_s1d$_ch@nn31}
```
