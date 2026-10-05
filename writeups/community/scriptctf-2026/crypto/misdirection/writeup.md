---
ctf: "scriptCTF 2026"
kategori: "Crypto"
challenge: "Misdirection"
flag: "scriptCTF{notwhatitseems}"
teknik: "115 bit habis dibagi 5 (bukan 8) → 23 grup 5-bit → hanya bermakna di bawah alfabet Bacon's cipher ASLI 24-huruf (I/J dan U/V berbagi simbol), bukan pemetaan 26-huruf modern"
---

# Misdirection — scriptCTF 2026 (Crypto, 160 poin)

## Deskripsi Singkat

Handout-nya satu baris 115 digit biner ASCII diikuti newline — artefak crypto sekecil mungkin, yang sendirinya sinyal untuk membaca tiap byte-nya dengan hati-hati. Hint: *"It is not what it is."*

## Analisis

**Baca bentuknya sebelum byte-nya.** Insting pertama untuk 115 bit adalah memotongnya jadi byte. Jangan. Lakukan aritmetika modular dulu:

```text
115 mod 8 = 3     ← menyingkirkan byte stream
115 mod 5 = 0     ← grup 5-bit pas persis
115 / 5   = 23    ← 23 simbol
```

Pilihan 115 bit yang persis, bukan 112 atau 120, disengaja. Grup 5-bit adalah bentuk khas dua cipher klasik: kode Baudot telegraf dan **Bacon's cipher**. Panjang 23-simbol wajar untuk panjang frasa flag CTF plus wrapper — semantik shift-in/shift-out Baudot butuh simbol ekstra untuk figures. Bacon cocok.

**Split jadi grup 5-bit.** Setiap nilai jatuh di `[0, 20]` — konfirmasi kedua bentuknya: alfabet 26-huruf akan memakai index sampai 25, tidak ada yang muncul. Index maksimum 20 persis rentang tabel Bacon 24-huruf (`0..23`).

**Misdirection-nya.** Percobaan natural pertama: petakan `00000..11001` ke `A..Z` dengan `A=0`. Hasilnya: `RCQIOSCSFMNSUHASISREELR` — semua huruf, tanpa digram jelas, tanpa prefix flag jelas. Cukup dekat untuk membuatmu terus mencoba — balik string-nya, invert bit-nya, balik tiap grup, XOR konstanta. Setiap variasi cuma lebih dari itu. Masalahnya bukan di bit stream atau grouping-nya; masalahnya di alfabet-nya.

**Alfabet asli Bacon.** Bacon's biliteral cipher (1623) memakai hanya **24 simbol** karena dua pasang huruf berbagi satu kode: `I/J` berbagi satu simbol, `U/V` berbagi satu simbol:

```text
index:     0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23
alphabet:  A B C D E F G H I K L  M  N  O  P  Q  R  S  T  U  W  X  Y  Z
```

Menerapkannya ke 23 index-nya menghasilkan:

```text
SCRIPTCTFNOTWHATITSEEMS
```

Split di batas natural: `SCRIPTCTF | NOT WHAT IT SEEMS` — plaintext-nya menyelesaikan judul, hint, dan body flag sekaligus.

## Eksploitasi / Solusi

Alfabet Bacon tidak bisa mengekspresikan kurung kurawal, case, spasi, atau underscore — hanya substitusi huruf 24-simbol. Prefix `SCRIPTCTF` menandai akhir wrapper event; body sisanya frasa 14-huruf kontinu `NOTWHATITSEEMS`. Menerapkan format flag scriptCTF tanpa mengarang pemisah:

```
scriptCTF{notwhatitseems}
```

## Catatan / Insight

Baca panjangnya dulu, dan baca alfabet historis sebelum yang modern. Keduanya adalah perbedaan antara decoder yang menghasilkan omong kosong dan decoder yang menghasilkan flag. Aritmetika modular (`115 mod 8 = 3`, `115 mod 5 = 0`) memaksa grouping-nya tanpa menyentuh bit-nya. Perbedaan Bacon vs alfabet-modern adalah seluruh challenge-nya — dan keduanya terdokumentasi di setiap referensi tentang cipher ini. 160 poin ini menghargai mengingat bahwa cipher klasik mendahului alfabet Inggris modern, bukan menulis kode baru.

## Flag

```
scriptCTF{notwhatitseems}
```
