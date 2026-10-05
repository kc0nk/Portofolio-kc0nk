---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Forensics"
challenge: "check-the-fine-print"
flag: "tjctf{wow_you_actually_read_it}"
teknik: "Byte 26 (compression method) IHDR PNG — field yang seharusnya selalu 0 — dipakai sebagai 1 bit per file di 248 PNG kecil"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# check-the-fine-print — TJCTF 2026 (Forensics)

## Deskripsi Singkat

Sebuah PNG dengan ZIP yang ditempel di ekornya (`binwalk` langsung memunculkannya) berisi 248 PNG kecil 19×9.

## Analisis & Eksploitasi

Setiap port stego standar kembali kosong — sampai kamu membaca **byte 26** dari tiap PNG. Byte itu adalah `compression method` milik IHDR, yang menurut spek PNG wajib bernilai `0`, dan merupakan field kedua paling sering diabaikan di forensik image setelah `bit-depth`. Beberapa file menyetelnya jadi `1` (ilegal). Satu bit per file × 248 file = 31 byte ASCII.

```python
bits = [open(f, "rb").read()[26] & 1 for f in sorted(glob("*.png"))]
print(bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)))
```

## Flag

```
tjctf{wow_you_actually_read_it}
```
