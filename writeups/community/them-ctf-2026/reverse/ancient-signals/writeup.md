---
ctf: "THEM?! CTF 2026"
kategori: "Reverse Engineering"
challenge: "Ancient Signals"
flag: "THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}"
teknik: "Kebocoran XOR PCM 8-bit dari region hening + hash FNV-1a atas potongan .text sebagai kunci XOR untuk flag asli"
---

# Ancient Signals — THEM?! CTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Sebuah player GUI Windows 64-bit (`player.exe`, memakai miniaudio + WinMM) dan payload biner (`transmission.dat`). Prompt soal bilang bahwa *software*-nya rusak dan flag ada di *tape*-nya. Ternyata kedua setengahnya sama-sama pengalih perhatian — ada dua jalur solve, tapi hanya satu yang membawa flag asli.

## Analisis

**Jalur 1 — Tape-nya (rickroll).** `transmission.dat` adalah PCM 8-bit unsigned yang di-XOR-enkripsi dengan kunci berulang 128-byte. Keheningan pada PCM 8-bit bernilai `0x80` (mid-range), jadi region hening mana pun di audio aslinya membocorkan kuncinya:

```python
key[p % 128] = data[p] ^ 0x80   # untuk p mana pun di region hening
```

Blok `0x50..0xCF` hening (ia berulang byte-demi-byte di `0xD0..0x14F`, yang hanya mungkin terjadi kalau kedua region ter-decode jadi sampel nol semua). Pulihkan kuncinya, XOR file-nya → `RIFF…WAVE`. Audio-nya adalah **Rick Astley** *Never Gonna Give You Up*. Ini bagian dari lelucon; ini **bukan** flag-nya.

**Jalur 2 — Player-nya (flag asli).** Sebuah blob 55-byte yang di-XOR-enkripsi tersimpan di section `.data` milik `player.exe` pada VA `0x140080000`. Kunci XOR-nya adalah **hash FNV-1a** dari potongan 80-byte `.text` — badan sebuah helper anti-tamper kecil di `0x1400032d0` yang mengecek 4 byte pertama input-nya adalah `"RIFF"`. Hitung hash-nya, XOR blob-nya.

## Eksploitasi / Solusi

Kalau kamu mengikuti prompt secara literal — perbaiki player, dengarkan tape — kamu akan berakhir mengemulasikan Windows dengan output audio hanya untuk mengonfirmasi rickroll. Jalur kode pencetak-flag di dalam `player.exe` digerbangi oleh `is_RIFF()` atas byte input mentah, dan `.dat` mentahnya diawali `08 CE 08 25`, bukan `RIFF`, jadi player selalu langsung berhenti dengan "Frequencies misaligned" tak peduli apa pun yang kamu "perbaiki".

## Catatan / Insight

**Pelajaran untuk defender:** helper anti-tamper yang *byte*-nya sendiri dipakai sebagai kunci bersifat self-protecting sekaligus self-incriminating sekaligus. Kalau satu instruksi ditulis-ulang oleh debugger atau di-hot-patch saat load, hash-nya berubah, kunci XOR-nya berubah, dan payload hasil decode jadi sampah. Layak diketahui dari kedua sisi (penyerang maupun pembela).

## Flag

```
THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}
```
