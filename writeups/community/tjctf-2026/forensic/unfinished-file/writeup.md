---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Forensics"
challenge: "unfinished-file"
flag: "tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}"
teknik: "File .crdownload Chrome; local file header ZIP self-describing walaupun central directory hilang; XOR satu-byte dengan crib"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# unfinished-file — TJCTF 2026 (Forensics)

## Deskripsi Singkat

File `.crdownload` parsial milik Chrome — bytes-on-wire dari `secret_archive.zip` yang belum selesai, diawali header `CRDL` milik Chrome (~0x100 byte).

## Analisis & Eksploitasi

ZIP-nya tidak punya central directory (download-nya dimatikan sebelum selesai), tapi **local file header itu self-describing**: telusuri signature `PK\x03\x04`, parsing manual, temukan `hidden/.flagdata` (47 byte, method store 0). Data-nya terenkripsi XOR satu-byte; XOR byte pertama (`0x36`) terhadap prefix plaintext yang diketahui `t` (karakter pertama `tjctf{`) → kunci = `0x42`. XOR seluruh 47 byte-nya.

## Flag

```
tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}
```
