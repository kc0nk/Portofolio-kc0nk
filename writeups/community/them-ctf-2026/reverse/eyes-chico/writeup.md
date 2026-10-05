---
ctf: "THEM?! CTF 2026"
kategori: "Reverse Engineering"
challenge: "Eyes Chico"
flag: "THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}"
teknik: "VM dengan control-flow flattening dan state dispatch yang mutasi sendiri; diselesaikan lewat emulasi dinamis dengan Unicorn"
sumber: "https://github.com/Abdelkad3r/themectf-2026"
---

# Eyes Chico — THEM?! CTF 2026 (Reverse Engineering)

## Deskripsi Singkat

`1983.exe` adalah crackme console seberat 22.5 KB — prompt `flag> `, membandingkan 113 byte input terhadap nilai yang dihitung sendiri oleh program. Bagian menariknya adalah *bagaimana* nilai itu dihitung:

- Tape instruksi 491-byte di `.rdata+0x580`.
- Jump table 36-entri di `.rdata+0x18`.
- Buffer stack 113-byte di `[rsp+0xbf]` yang ditulis satu byte per satu selagi VM dieksekusi.
- Pengecekan adalah `pxor` SIMD atas chunk input 16-byte vs buffer, `por` ke `xmm1`, horizontal-reduce, cabang berdasarkan nol.

## Analisis

Prolog VM-nya **memutasi state selama dispatch**:

```text
k = ((ecx*2) XOR r11 XOR state[state[8]] XOR opcode) & 3
state[esi]          ^= ...
state[state[14]]    ^= ...
state[state[15]]    ^= ...
```

Nilai opcode yang sama di dua titik berbeda punya efek samping berbeda, karena index yang dipakai untuk memutasi state vector bergantung pada state sebelumnya. Control-flow flattening ditambah sink *"WRONG-EXIT"* sebagai target default jump-table membuat rekonstruksi statis jadi kerja berat.

Jalan keluarnya adalah **emulasi dinamis lewat Unicorn**:

1. Petakan setiap section PE pada VA yang diinginkannya.
2. Reproduksi prolog `main` yang persis — seed state, nilai register, layout stack.
3. Loncat ke entry point dispatcher VM.
4. Hook setiap penulisan ke `[rsp+0xbf … +0x130)`.
5. Ketika RIP mencapai instruksi `leaq "flag> ", %rcx`, VM sudah selesai dan buffer stack sudah terisi penuh. Baca 113 byte-nya.

## Eksploitasi / Solusi

```bash
$ ./solve.py
[+] loaded .text  at 0x140001000 size 0x2400
[+] loaded .data  at 0x140004000 size 0x200
[+] loaded .rdata at 0x140005000 size 0x1400
[+] emulating 0x140002ac0 -> 0x140002b80
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

## Catatan / Insight

Flag-nya mengeja seluruh teknik pertahanan yang dipakai ("reverse execution VM with mutating registers and control flow flattening makes static analysis painful").

**Pelajaran untuk defender:** kombinasi anti-static-analysis (control-flow flattening + dispatch yang memutasi state + string umpan) menaikkan ongkos analisis statis secara drastis, tapi emulasi dengan hook adalah jawaban berongkos konstan. Kalau tugas binary-mu pada akhirnya adalah menulis byte yang benar ke sebuah buffer, penyerang yang bisa menjalankannya di CPU yang terkontrol pada akhirnya akan bisa membaca byte itu kembali.

## Flag

```
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```
