---
ctf: "DalCTF 2026"
kategori: "Crypto"
challenge: "All's Fair in Love and CTFs"
flag: "dalctf{ANYTHINGFORTHEFLAG}"
teknik: "Playfair dengan kotak alfabet POLOS (tanpa scramble keyword); jebakan format flag — plaintext huruf besar mentah, bukan lowercase-underscore"
sumber: "https://github.com/Abdelkad3r/dalctf-2026"
---

# All's Fair in Love and CTFs — DalCTF 2026 (Crypto)

## Deskripsi Singkat

Handout-nya berupa gambar grid 5×3 yang hanya menampilkan kolom bernomor ganjil dari kotak Polybius / Playfair 5×5 standar (I/J digabung):

```
A _ C _ E
F _ H _ K
L _ N _ P
Q _ S _ U
V _ W _ X
```

## Analisis

Isi kembali bagian yang kosong. Hasilnya urutan A–Z polos dengan I=J, **tanpa scramble keyword sama sekali**:

```
A B C D E
F G H I K
L M N O P
Q R S T U
V W X Y Z
```

Ciphertext-nya `CLDYIKMHILSUKCLQBF` — 18 karakter, 9 digram. Terapkan dekripsi Playfair standar:

- Baris sama → geser tiap huruf ke kiri
- Kolom sama → geser tiap huruf ke atas
- Persegi panjang → tukar kolom

```
CL → AN     DY → YT     IK → HI     MH → NG
IL → FO     SU → RT     KC → HE     LQ → FL
BF → AG
```

→ `ANYTHINGFORTHEFLAG`.

## Eksploitasi / Solusi — Jebakan Format Flag

Gaya bawaan DalCTF adalah `dalctf{lowercase_with_underscores}`, jadi tebakan pertama yang alami adalah `dalctf{anything_for_the_flag}`. **Itu salah.** Flag yang diterima mempertahankan plaintext huruf besar mentah apa adanya:

```
dalctf{ANYTHINGFORTHEFLAG}
```

Untuk challenge crypto DalCTF, jangan otomatis menormalisasi plaintext hasil dekripsi jadi lowercase/underscore sebelum submit — coba plaintext mentahnya dulu.

## Catatan / Insight

**Kelas bug:** cipher klasik tanpa alfabet berkunci; jebakan normalisasi format flag.

## Flag

```
dalctf{ANYTHINGFORTHEFLAG}
```
