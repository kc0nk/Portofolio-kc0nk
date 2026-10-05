---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Misc"
challenge: "jumper"
flag: "tjctf{PAST_THE_WALL}"
teknik: "Godot 4.6 PCK dengan directory offset di slot baru + entry offset relatif file_base 0x70; 8 dari 56 ColorRect punya rotasi/scale non-default"
---

# jumper — TJCTF 2026 (Misc)

## Deskripsi Singkat

Platformer Godot 4.6 yang di-export ke WebAssembly, membawa packfile `.pck`. Dua keanehan format non-obvious membuat soal ini lebih sulit dari kelihatannya.

## Analisis

1. **Offset directory PCK Godot 4.6 tidak berada di posisi yang disebut dokumentasi PCK 1.x.** Godot 4.6 menyimpannya di slot u64 yang sebelumnya reserved pada offset header `0x20`.
2. **Offset entry relatif terhadap `file_base = 0x70`**, bukan terhadap awal file.

## Eksploitasi / Solusi

Parsing PCK-nya, ekstrak `f.scn` (`PackedScene` biner), telusuri stream Variant-nya. Scene-nya mengandung 56 node `ColorRect`. **Delapan di antaranya punya rotasi atau scale non-default** — editor Godot akan merendernya berotasi, tapi PCK dumper naif yang hanya membaca `offset` dan `color` akan merendernya sebagai rectangle axis-aligned, meruntuhkan goresan diagonal huruf jadi celah tak terlihat. Render setiap rect sebagai polygon 4-sudut, terapkan scale dan rotasi di sekitar origin lokal, translasikan dengan offset, gambar, baca flag-nya.

## Flag

```
tjctf{PAST_THE_WALL}
```
