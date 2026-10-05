---
ctf: "BDSec CTF 2026"
kategori: "Pwn (Binary Exploitation)"
challenge: "Muktir Shongket"
flag: "BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}"
teknik: "Verifier tidak menelusuri target ROUTE, executor menerjemahkannya jadi jmp rel32 x86; ROUTE +2 melompat ke tengah literal SIGNAL yang jadi mov eax,0x401bb0; call rax; ret"
sumber: "https://github.com/Abdelkad3r/BDSecCTF-2026"
---

# Muktir Shongket — BDSec CTF 2026 (Pwn, 100 poin)

## Deskripsi Singkat

ELF Linux menu-driven yang menerima "transmisi ter-encode" hex, memverifikasinya sebagai bytecode lima-opcode (`WAIT`, `SIGNAL <literal 8-byte>`, `ROUTE <s8>`, `END`, `FREEDOM`), lalu meng-JIT-translasi byte yang sama jadi halaman executable berbasis `mmap`+`mprotect`.

## Analisis — Bug-nya

Verifier menelusuri bytecode secara sekuensial: `WAIT/SIGNAL/ROUTE/END` diterima, `FREEDOM` ditolak. `ROUTE` hanya dicek target-nya in-bounds (`current_offset + 2 + operand < length`) — **verifier tidak pernah menelusurinya**. Executor menurunkan `WAIT → 0x90`, `END → 0xc3`, `SIGNAL imm64 → eb 08 <8 byte literal>`, dan `ROUTE x → e9 <x sebagai rel32 sign-extended>`.

Karena `SIGNAL` menaruh 8 byte literal-nya ke halaman executable tapi langsung melompatinya dengan `jmp +8`, `ROUTE` mana pun yang mendarat di tengah literal itu mengubah byte-byte tersebut jadi instruksi.

## Eksploitasi / Solusi

Payload: `30 02` (`ROUTE +2`) mengejar ke dalam literal `SIGNAL` `b8 b0 1b 40 00 ff d0 c3` (`mov eax, 0x401bb0; call rax; ret`), yang memanggil internal flag-printer di alamat tetap milik binary non-PIE.

```
Hex total: 300220b8b01b4000ffd0c340   (12 byte)
```

```
BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}
```

## Catatan / Insight

**Prinsip panduan:** *verifier* dan *executor* milik Muktir Shongket tidak sepakat soal apa yang dilakukan opcode `ROUTE`: verifier menyebutnya metadata inert, executor menerbitkan jump relatif unconditional. Attacker tidak butuh memory-corruption 0-day atau rantai ROP — bug-nya secara harfiah adalah ketidaksepakatan niat yang terlihat di `git blame` antara dua fungsi di file yang sama, dan primitive-nya keluar begitu kamu memilih operasi yang ditangani berbeda oleh kedua sisi.

Diff verify vs execute per-opcode memunculkan `ROUTE` sebagai satu-satunya opcode di mana kedua sisi melakukan hal yang materially berbeda — pengecekan semacam ini (hanya dua operasi yang menyentuh buffer bytecode: verify dan execute, lima opcode untuk dipertimbangkan) membuat ketidaksepakatannya langsung tampak begitu di-tabulasi berdampingan.

**Pelajaran untuk defender:** verifier bytecode apa pun yang tidak menelusuri **setiap** jalur kontrol-flow yang bisa dijangkau executor (termasuk operand `ROUTE`/jump) adalah verifier yang tidak benar-benar memverifikasi apa yang akan dieksekusi.

## Flag

```
BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}
```
