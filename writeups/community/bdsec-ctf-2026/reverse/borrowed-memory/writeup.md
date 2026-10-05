---
ctf: "BDSec CTF 2026"
kategori: "Reverse Engineering"
challenge: "Borrowed Memory"
flag: "BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}"
teknik: "Tabel memori xorshift 0x800-byte ditambal jadi tape opcode VM 12-langkah; input user adalah rantai 12 offset, checksum-gated per-langkah, blob flag 40-byte didekripsi lewat XOR 4-sumber"
sumber: "https://github.com/Abdelkad3r/BDSecCTF-2026"
---

# Borrowed Memory — BDSec CTF 2026 (Reverse Engineering, 460 poin)

## Deskripsi Singkat

ELF PIE x86-64 **stripped**. Prompt-nya: *"Return what was borrowed."* plus hint `"0x???? -> 0x???? -> 0x????"` — input-nya bukan password, tapi **rantai 12 offset**. String `"BORROWED MEMORY"` + hint tersebut menandakan input user adalah rantai alamat, bukan passphrase — dan keberadaan region `.bss` besar plus blob `.rodata` dekat exit path melokalisasi tape instruksi hasil generate maupun blob flag terenkripsi sebelum satu instruksi pun di-disassembly.

## Analisis

`main` membangkitkan tabel pseudo-random 0x800-byte di `.bss:0x4080` dari seed `0x91e10da5` lewat mixer bergaya xorshift:

```c
state = state + i + 0x045d9f3b;
state = (state << 13) ^ state;
state ^= state >> 17;
state ^= state << 5;
table[i] = (state >> 11) & 0xff;
```

Byte/word/dword terpilih lalu ditambal (misal word di offset `0x20 = 0x7d95`) untuk mengkodekan tape opcode VM. Tiap input user harus memenuhi `0x4000 <= v <= 0x47ff` dan cocok dengan `0x4000 + current_offset`. Validator membaca `opcode = ((current_offset >> 3) ^ table[current_offset]) & 0xff`; hanya `0xc0..0xc3` diterima. Tiap opcode menghitung offset berikutnya secara berbeda (byte tabel terdekat, counter bergulir, jumlah rotasi kecil, state validator saat ini); checksum dua-byte di `table[current_offset+8..+9]` menggerbangi tiap langkah. Langkah keduabelas harus menghasilkan `next_offset == 0xFFFF`.

**VM-nya sepenuhnya di dalam binary** — generator tabel, patch, dispatch opcode, checksum, loop dekripsi, semuanya bisa direproduksi di Python.

## Eksploitasi / Solusi

Jalur sukses mendekripsi blob 40-byte di `.rodata:0x2220` lewat loop XOR empat-sumber:

```c
c = enc[i]
    ^ (0x1d*i & 0xff)
    ^ validator_output[(5*i+1) % 12]
    ^ ((validator_state[i % 12] >> (8*(i & 3))) & 0xff)
    ^ (user_inputs[(7*i+3) % 12] & 0xff);
```

Reimplementasi seluruh pipeline (generator tabel → patch → walk 12-langkah dengan checksum → loop dekripsi) di Python, temukan rantai 12 offset yang valid, lalu dekripsi blob-nya:

```
BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```

## Catatan / Insight

**Pelajaran:** utamakan reasoning statis dibanding dynamic tracing ketika transform-nya bisa dibalik dan target-nya ada di `.rodata`. Challenge 460 poin ini *terlihat* ingin instrumentasi dinamis karena ada VM-nya, tapi VM itu sepenuhnya hidup di dalam binary — generator tabel, patch, dispatch opcode, checksum, loop dekripsi, semuanya bisa direproduksi di Python tanpa menjalankan binary-nya sama sekali.

## Flag

```
BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```
