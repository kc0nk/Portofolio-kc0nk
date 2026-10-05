---
ctf: "BhAcKAri CTF 2026"
kategori: "Reverse Engineering"
challenge: "Mystery (Python C-extension)"
flag: "bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}"
teknik: "C-extension ter-strip yang meng-hash dirinya sendiri (SHA-256+CRC32) untuk menurunkan kunci AES-256-CTR; seluruh rantai bisa diselesaikan offline dari byte .so-nya sendiri"
---

# Mystery (Python C-extension) — BhAcKAri CTF 2026 (Reverse Engineering)

## Deskripsi Singkat

```text
$ file mystery.so
ELF 64-bit LSB shared object, x86-64, dynamically linked, stripped
$ wc -c flag.enc
46 flag.enc
```

C-extension Python ter-strip yang meng-import OpenSSL EVP (SHA-256 + AES-256-CTR) dan toolkit anti-debug standar (`ptrace`, `prctl`, `dladdr`, pengecekan env `LD_PRELOAD`/`LD_AUDIT`). Module-nya mengekspos empat method: `mystery.stage(index, value)`, `mystery.reveal()`, `mystery.easy_access()` (mengembalikan flag umpan `BhackariCTF{that_was_too_easy... or_was_it?}`), dan `mystery.get_runtime_info()`. Flag asli berawalan huruf kecil `bhackariCTF{...}` dan datang dari `reveal()`.

## Analisis — Setiap Layer Deterministik dari Byte `mystery.so` Sendiri

Seluruh challenge ini bisa diselesaikan **offline dalam Python murni tanpa mengeksekusi binary-nya sama sekali**:

1. `sha = SHA-256(mystery.so)` — fungsi `entry.init2 @ 0x2916` milik module menjalankan `dladdr → fopen → EVP_DigestUpdate` atas file-nya sendiri di disk.
2. `noise = CRC32(mystery.so)` — `crc32` milik zlib cocok dengan inversi akhir hand-rolled kode C-nya.
3. `table0[64]` diturunkan dari `sha` lewat mixer bergaya SplitMix di `entry.init2` (fase golden-ratio multiplier, fase xorshift* multiplier).
4. Empat fungsi pengecekan stage mengembalikan nilai deterministik berdasarkan indeks byte tabel dan `sha`/`noise`.
5. `stage()` menyimpan `(value ^ 0xcafebabe) - index * 0x1234` di `0x62c0 + (i−1) * 4`.
6. `reveal()` mencampur-berantai 4 secret tersimpan + `sha` + `noise` jadi kunci AES 32-byte.
7. AES-256-CTR dengan kunci itu dan **IV nol 16-byte** mendekripsi `flag.enc`.

## Eksploitasi / Solusi

```bash
$ ./solve.py
bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}
```

## Catatan / Insight

**Pelajaran untuk defender:** **primitive anti-debug tidak melindungi konten yang diturunkan dari byte binary itu sendiri.** Langkah `dladdr → fopen → SHA-256(self)` milik `mystery.so` adalah bukti telaknya — begitu kamu menemukannya, seluruh materi keying bisa direproduksi offline tanpa menjalankan module-nya. Pengecekan `ptrace`/`LD_AUDIT`/`prctl` hanyalah dekorasi karena tidak satu pun terpicu kalau kamu tidak pernah `import mystery`.

## Flag

```
bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}
```
