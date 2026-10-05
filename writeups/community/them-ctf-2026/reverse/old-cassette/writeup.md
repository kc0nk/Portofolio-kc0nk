---
ctf: "THEM?! CTF 2026"
kategori: "Reverse Engineering"
challenge: "Old Cassette"
flag: "THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}"
teknik: "ROM CHIP-8; state-machine 16-bit masuk ke short cycle (tail 329, cycle 34), 32 ronde melukis flag ke layar"
sumber: "https://github.com/Abdelkad3r/themectf-2026"
---

# Old Cassette — THEM?! CTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Handout-nya adalah ROM CHIP-8 sebesar 3.282 byte (`main.bin`). Opcode pertamanya adalah `00E0 1280` — `CLS; JP 0x280` — dan ROM ini tidak pernah meminta input. Alih-alih, ia melukis flag ke layar monokrom 64×32, memakai state machine yang diiterasi dengan jumlah yang absurd: sampai ~10¹³ langkah encoder per karakter.

## Analisis

Emulasi naif akan makan waktu berjam-jam. Jalan keluarnya adalah menyadari bahwa state machine di `0x2C0` adalah fungsi murni atas 16-bit state `(VA, VB)` yang di-seed pada `(0xA7, 0xC3)`:

- **Trajektorinya masuk ke cycle pendek hampir seketika.** Panjang tail **329**, panjang cycle **34**.
- Begitu cycle-nya diketahui, `state_at(N)` jadi konstan-waktu: `if N < 329: states[N] else: states[329 + ((N − 329) mod 34)]`.

Rutin utama di `0x900` menjalankan **32 ronde**. Setiap ronde mengiterasi encoder sejumlah tertentu yang hardcoded (ronde 0–15 memakai counter eksplisit `4^k`; ronde 16–31 memanggil wrapper yang memicu `255 × (2³² − 1) ≈ 2⁴⁰` langkah encoder per ronde), lalu menghitung:

```text
chr = mem[TBL[VA & 7] + off] ^ VA ^ VB
```

di mana `TBL` adalah tabel dispatch 9-byte di `0x322`.

## Eksploitasi / Solusi

Replay semua 32 ronde memakai shortcut cycle-nya, urutkan karakter yang dihasilkan berdasarkan `(yp, xp)` untuk membaca layar dari kiri-ke-kanan, atas-ke-bawah:

```text
THEM?!CTF{
0LD_T4P3_N
3V3R_D1E5K
7}
```

## Catatan / Insight

**Pelajaran untuk defender:** obfuscator berbentuk state-machine yang terlihat mahal secara eksponensial biasanya murah secara polinomial begitu cycle-nya ditemukan. Trajektori dari fungsi murni *apa pun* atas state space kecil `S` selalu masuk ke sebuah cycle dalam `|S|` langkah — itu argumen satu baris ala Floyd's tortoise-and-hare, bukan sebuah eksploit.

## Flag

```
THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}
```
