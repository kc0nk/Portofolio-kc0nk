---
ctf: "ASIS CTF Quals 2026"
kategori: "Reverse Engineering"
challenge: "LeakMeAk"
flag: "ASIS{haaducrcplmekhylrozcxyxzuizs}"
teknik: "Hash non-injective H=word*0x9e3779b9 XOR mix; 7 persamaan siklik diselesaikan z3, Unicorn sebagai oracle eksak untuk state machine mix, DFS atas kandidat kecil"
sumber: "https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Reverse/LeakMeAk"
---

# LeakMeAk — ASIS CTF Quals 2026 (Reverse Engineering, Medium)

## Deskripsi Singkat

ELF PIE ter-strip. `main` membaca `%127s`, lalu tiga gerbang murah: panjang harus 34, prefix `ASIS{`, sufiks `}`. Jadi flag-nya `ASIS{` + **28 byte dalam** + `}`.

## Analisis — Hash Internalnya

Fungsi intinya adalah satu fungsi yang sangat ter-obfuskasi. 28 byte dikonsumsi **empat per-waktu** sebagai big-endian word dan dilipat jadi tujuh dword 32-bit: `H[i] = (word_i * 0x9e3779b9) XOR mix_i`. `0x9e3779b9` adalah konstanta golden-ratio, dan `mix_i` dihasilkan state machine per-byte — counter character-class, perbandingan `> 'Y'`, dan dua array stack kecil. Untuk prefix tetap, `mix_i` hanya bergantung empat byte saat ini — entropi rendah.

**Kondisi penerimaan.** Fungsi ini tidak pernah early-exit; ia mengakumulasi error mask di `ecx` dan di akhir mengecek semuanya sekaligus: `ecx == 0` (state machine byte-processing tidak boleh pernah OR bit error), **tujuh persamaan siklik** pada dword terhadap dua tabel rodata (`(ror(H[i%7],13) + H[i-1]) XOR tableB[i] == tableA[i]` untuk `i=1..7`), **poly-33 hash** dari ketujuh dword sama dengan `0xddaacf25`, remix 64-round-nya sama dengan `0x376a3d36` (redundant, deterministik dari hasil poly), dan dua pengecekan low-bit pada array state internal `s30`.

**"Trust issues" — hash-nya tidak injective.** `H[i] = word_i * const XOR mix_i` memetakan empat byte ke satu dword, tapi pasangan `(word, mix)` berbeda bisa bertabrakan ke `H` yang sama. Diberikan target `H[i]`, tiap kandidat `mix_i` menghasilkan satu `word_i = (H[i] XOR mix_i) * inv(const)`, jadi satu dword punya beberapa preimage yang bisa dicetak — inilah "kebocoran" yang diisyaratkan judulnya. Yang mengembalikan keunikan adalah sisanya: state machine `ecx` dan pengecekan `s30` menautkan grup empat-byte bersama, jadi hanya satu string 28-byte penuh yang memenuhi **semuanya**.

## Eksploitasi / Solusi

**Tahap 1 — dword internal, dengan z3.** Tujuh persamaan siklik adalah tujuh constraint pada tujuh unknown 32-bit. Memberikannya ke z3 (dengan `C[i] = tableA[i] XOR tableB[i]`), plus target poly-33 sebagai pengecekan konsistensi, memberi solusi **unik**:

```python
for i in range(1, 8):
    solver.add(RotateRight(H[i % 7], 13) + H[i - 1] == C[i])
edx = BitVecVal(0, 32)
for h in H:
    edx = edx * 33 ^ h
solver.add(edx == 0xddaacf25)
```

**Tahap 2 — oracle Unicorn untuk mix.** Alih-alih membalikkan state machine `mix` yang rumit dengan tangan, `solve.py` mengemulasikan fungsi pengecekan dengan **Unicorn**. Masuk tepat setelah pengecekan panjang/prefix dengan flag ditulis ke buffer stack, meng-hook penulisan dword untuk membaca `(H_i, mix_i, ecx_i)` di tiap iterasi, dan meng-hook dua situs `puts` (granted/denied) untuk vonisnya. Emulasinya cycle-accurate terhadap binary asli (~0.16 ms per run).

**Tahap 3 — invert dan DFS.** Untuk tiap grup 4-byte `i`, diberikan target `H[i]`: oracle men-sample set kecil nilai `mix_i` yang bisa dijangkau untuk prefix saat ini; tiap `mix` dibalik jadi `word_i = (H[i] XOR mix) * inv(0x9e3779b9)`, dan yang printable dengan `H` ter-emulasi cocok serta `ecx` bersih jadi kandidat. DFS atas kandidat-kandidat ini (biasanya satu atau dua per posisi) hanya mempertahankan string lengkap yang **diterima** checker-nya.

```
$ python3 solution/solve.py
[+] internal dwords H = ['0xcf6a545', '0x89397a88', ...]
[+] 1 string(s) accepted by the checker
[+] flag: ASIS{haaducrcplmekhylrozcxyxzuizs}
```

Dikonfirmasi terhadap servis live — "Access Granted! Correct Flag.", dan perubahan satu byte apa pun memberi "Access Denied!". Flag-nya terbaca seperti acak, bukan leetspeak — itu properti challenge-nya (checker lossy dengan tepat satu fixed-point yang printable), bukan decode yang terlewat.

## Catatan / Insight

- **Checker yang mengakumulasi error dan membandingkan sekali tidak punya timing oracle** — tidak bisa dikupas karakter-demi-karakter. Jalan masuknya adalah memodelkan seluruh predikat-nya, dan z3 plus emulator melakukannya tanpa membalik tiap cabang dengan tangan.
- **Emulasikan bagian yang tahan terhadap pembacaan statis.** State machine `mix`-nya genuinely rumit; alih-alih mentranskripsikannya, Unicorn *adalah* ground truth-nya, dan satu hook di dword store mengubahnya jadi oracle eksak.
- **Hash lossy plus constraint tambahan tetap bisa unik.** Non-injectivity memberi collision per-dword, tapi state machine dan pengecekan low-bit menautkan grup-grupnya; mengenumerasikan pohon kandidat kecil dan bertanya ke checker untuk vonisnya meruntuhkannya jadi satu jawaban.

## Flag

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```
