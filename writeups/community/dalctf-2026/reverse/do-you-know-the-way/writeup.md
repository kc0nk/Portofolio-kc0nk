---
ctf: "DalCTF 2026"
kategori: "Reverse Engineering"
challenge: "Do you know the way?"
flag: "dalctf{symb0ls_4r3_4lw4ys_3xtr3m3ly_h3lpfu1}"
teknik: "ELF x86-64 ter-pack UPX yang simbolnya tidak di-strip; 44 fungsi f_i per-byte di-brute-force, gerbang runtime di main hanyalah dekorasi"
---

# Do you know the way? — DalCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

ELF x86-64 yang di-pack UPX dengan satu gerbang runtime yang sepenuhnya dekoratif. Binary-nya mencetak:

> Do you know the way? Are there any symbols around to help you?

Kalimat kedua itu adalah *seluruh* petunjuknya — binary-nya tidak di-strip. Setelah `upx -d`, symbol table memperlihatkan:

- `f_0 … f_43` — 44 fungsi kecil, satu per byte flag
- `rol8`, `ror8` — helper rotate 8-bit
- `expected` — array 44-byte di `.data:0x3020`

## Analisis — Umpan di `main`

`main` kira-kira melakukan:

```c
fgets(input, 44, stdin);
for (int i = 0; i < 44; i++) {
    idx = rand() % 44;
    if (i == idx) return;          // diam-diam keluar
    if (!f_i(input[i])) return;    // byte salah
}
puts("Good job!");
```

Pengecekan `idx` acak itu berarti saat runtime rantainya *tidak pernah* selesai — bahkan dengan flag yang benar biasanya kamu tidak mendapat apa-apa. **Jangan coba selesaikan secara dinamis.** Rantai pengecekannya sendiri adalah puzzle-nya; gerbang runtime cuma dekorasi yang dirancang membuat fuzzing `pwntools` naif kehabisan waktu.

## Eksploitasi / Solusi — Emulasi Setiap `f_i`

Setiap `f_i` adalah transformasi pendek atas `input[i]`: `xor`, `add`, `sub`, `mul` (lewat shift+add), `rol8`, `ror8`, bitwise `not`, lalu membandingkan hasilnya dengan `expected[i]`. Ambil tiap fungsi dengan radare2:

```
r2 -A checker
[0x...]> pdf @ sym.f_38
```

Buat emulator Python kecil yang mem-brute-force satu byte input per `i`:

```python
for b in range(256):
    if f_i(b) == expected[i]:
        flag += chr(b); break
```

**Jebakan kecil:** `f_38` mengandung `not eax` yang mudah terlewat saat parsing — percobaan pertama menghasilkan `dalctf{symb0ls_4r3_4lw4ys_3xtr3m3ly_h3.pfu1}` alih-alih `…h3lpfu1}`. Membaca ulang disassembly dengan lebih teliti mengembalikan `not` itu ke tempatnya.

## Catatan / Insight

**Kelas bug:** binary yang membawa simbol dengan gerbang runtime dekoratif; fungsi pengecekan statis per-byte yang mudah di-brute-force. Flag-nya sendiri mengeja pelajarannya: *"symbols are always extremely helpful"*.

## Flag

```
dalctf{symb0ls_4r3_4lw4ys_3xtr3m3ly_h3lpfu1}
```
