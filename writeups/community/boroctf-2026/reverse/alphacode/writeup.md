---
ctf: "boroCTF 2026"
kategori: "Reverse Engineering"
challenge: "AlphaCode"
flag: "boroCTF{r3verse_by_guessncheck}"
teknik: "DSL kustom dengan enam opcode; aturan parser 'satu zm per program' sebenarnya adalah 'satu fungsi terbuka dalam satu waktu', sehingga bisa menumpuk banyak literal di queue lalu digabung sesuai template gauntlet"
---

# AlphaCode — boroCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Ini adalah soal reverse **paling sulit** dalam writeup ini. Handout berisi dua file `.ac` (satu mencetak "hello world", satu lagi membaca nama lalu mencetak "hello {name}"). Remote-nya adalah sebuah "ALPHACODE COMPILER" dengan dua mode: mode Compile yang menjalankan snippet kamu terhadap stdin milikmu sendiri, dan mode **Gauntlet** yang menjalankan snippet kamu tiga kali dengan tiga set input tetap, mengharapkan setiap run mencetak persis:

```
Hello I am {input 3}, and I like {input 2}.
I hate {input 1}.
```

Flag keluar kalau ketiga run cocok semua.

## Analisis

**Encoding literal.** Setiap token pada baris literal terdiri dari 1–5 huruf kecil yang di-decode menjadi satu byte ASCII yang bisa dicetak:

```
ord(ch) = 32 + Σ letter_index(c)        di mana 'a' = 0 ... 'z' = 25
```

Contoh: `awzz` → `0+22+25+25 = 72` → `chr(72+32) = 'h'`. Karena jumlahnya selalu non-negatif, byte minimum yang bisa di-encode adalah spasi (32). Newline (10) **tidak bisa** di-encode di dalam literal — ini penting untuk langkah berikutnya.

**Penemuan opcode.** Dengan mencoba setiap kombinasi `zz <aa..zz>` dan mengklasifikasikan responsnya (`Invalid line N` vs eksekusi diam-diam), ditemukan enam opcode valid:

| Op | Efek |
|---|---|
| `zz fi` | baca satu baris dari stdin |
| `zz fo` | cetak front efektif saat ini + `\n` |
| `zz fr` | menangkap / memperpanjang prefix yang tertunda (pending) |
| `zz dp` | pop front, terapkan pending prefix ke front baru |
| `zz dx` | rotasi queue ke kiri (front → back) |
| `zz di` | menutup body sebuah fungsi |

Model "naif" untuk `zz fr` — "prefix-kan front saat ini ke setiap item queue selanjutnya" — cocok untuk `helloyou.ac`, tapi memprediksi output yang salah begitu queue tumbuh lebih dari dua item. Setelah probing lebih lanjut, semantik sebenarnya adalah:

```
state: queue Q, pending P (str | None), flag (bool)

fr:  if flag: P = P + Q[0]            # tambahkan selama flag masih "panas"
     else:    P = Q[0]                # kalau tidak, timpa
     flag = True

fo:  if flag: print P + Q[0] + '\n'
     else:    print Q[0] + '\n'
     P = None; flag = False           # SELALU membersihkan P dan flag

dp:  Q.pop(0)
     if P: Q[0] = P + Q[0]            # terapkan pending, tapi PERTAHANKAN P
     flag = False

dx:  rotasi Q ke kiri                 # P dan flag dipertahankan
```

Tiga perilaku yang tidak terduga: `dp` **mempertahankan** `P` setelah menerapkannya (jadi rangkaian `dp` yang berurutan akan menempel-ulang prefix yang sama), `fo` **selalu** membersihkan `P`, dan `fr` **menambahkan (append)** ke `P` selama flag masih panas dari `fr` sebelumnya.

**Celah aturan parser.** Bahkan dengan model yang lebih lengkap ini, setiap baris yang dicetak adalah gabungan dari item-item yang diambil dari `{L, in1, in2, in3}`, dan input gauntlet tidak pernah mengandung string pemisah. Concatenation biasa saja tidak bisa menyisipkan teks tetap di antara dua input hanya dengan satu literal.

Celahnya: aturan parser bukan "satu `zm` per program". Aturan sebenarnya adalah "satu fungsi *terbuka* dalam satu waktu". Begitu fungsi yang sedang aktif sudah dipanggil (di-close), membuka `zm` lain jadi sah-sah saja. Ini memungkinkan kita menumpuk sejumlah bebas potongan literal:

```
zm a / <literal A> / zz di / a / zm b / <literal B> / zz di / b / fo / dp / fo
```

Terverifikasi di compiler live: snippet di atas mencetak `B\nA\n`.

## Eksploitasi / Solusi

**Membangun output gauntlet.** Lima definisi fungsi (tiga di antaranya membawa `zz fi`) membangun queue berikut:

```
[ L1="Hello I am ",  in3,  L2=", and I like ",  in2,  L3=".",  L4="I hate ",  in1,  L5="." ]
```

Pemanggilan `fi` terjadi sesuai urutan eksekusi, bukan urutan deklarasi fungsi yang mendefinisikannya. Dengan memanggil `e`, `d`, `c`, `b`, `a` dalam urutan itu, tiga panggilan `fi` di dalam `d`, `b`, `a` akan mengonsumsi `in1`, `in2`, `in3` sesuai urutan baca alami, sementara urutan pemanggilan itu sendiri mendorong `L5, L4, L3, L2, L1` ke depan queue. Empat pasangan `fr; dp` meringkas lima item pertama, `fo` mencetak baris 1, `dp` membuang item, dua pasangan `fr; dp` lagi + `fo` mencetak baris 2.

**Bentuk solver** (kode lengkap ada di [`reverse/AlphaCode/solve.py`](https://github.com/Abdelkad3r/boroCTF-2026/tree/main/reverse/AlphaCode)):

```python
snippet = "\n".join([
    "zm e", enc("."),                "zz di", "e",
    "zm d", enc("I hate "),  "zz fi","zz di", "d",
    "zm c", enc("."),                "zz di", "c",
    "zm b", enc(", and I like "), "zz fi", "zz di", "b",
    "zm a", enc("Hello I am "), "zz fi", "zz di", "a",
    "zz fr","zz dp","zz fr","zz dp",
    "zz fr","zz dp","zz fr","zz dp","zz fo",
    "zz dp",
    "zz fr","zz dp","zz fr","zz dp","zz fo",
    "ex",
])
```

`enc` adalah encoder literal: setiap karakter menjadi token 4-huruf lowercase yang jumlah letter-index-nya sama dengan `ord(ch) - 32`. Edge case yang harus diperhatikan: token hasil encoding tidak boleh diawali `zz` (karena parser akan menelannya sebagai opcode dan membuang literalnya). Encoder mengatasi ini dengan menurunkan huruf pertama dari `z` ke `y` dan menambah slack ke huruf berikutnya.

Setelah disubmit ke gauntlet, server mencetak tiga output test lalu:

```
You may be worthy of this flag: boroCTF{r3verse_by_guessncheck}
```

## Catatan / Insight

Flag itu sendiri adalah lelucon meta: soal ini memang benar-benar tentang reverse engineering lewat cara tebak-dan-cek (guess-and-check) terhadap semantik opcode yang tidak didokumentasikan.

## Flag

```
boroCTF{r3verse_by_guessncheck}
```
