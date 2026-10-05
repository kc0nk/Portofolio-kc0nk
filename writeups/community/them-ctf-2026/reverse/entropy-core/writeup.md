---
ctf: "THEM?! CTF 2026"
kategori: "Reverse Engineering"
challenge: "Entropy Core"
flag: "THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}"
teknik: "VM bytecode 64-bit 16-register, 30 opcode; DFS backtracking dengan preferensi ASCII printable untuk menemukan input yang valid"
---

# Entropy Core — THEM?! CTF 2026 (Reverse Engineering)

## Deskripsi Singkat

`entropy_core.exe` adalah wrapper C MinGW seberat 134 KB yang membungkus sebuah VM buatan sendiri:

- 16 register, 64-bit.
- 30 opcode yang bisa dicapai lewat jump table `cmpb $0x61` di `0x1400050c0`.
- Program bytecode 284-byte tertanam di `.rdata` pada `0x140005260`.
- Membaca 36 byte input, menjalankan tiap byte lewat hash per-byte yang mencampurnya ke `R10`, membandingkan byte rendahnya terhadap ciphertext 36-byte yang tersimpan di ekor program.

## Analisis

Dua jebakan static-analysis membuat reverse-nya lebih sulit dari yang terlihat:

1. **Umpan kunci RC4.** Sebuah struktur 232-byte terlihat seperti setup KSA RC4; kunci sebenarnya cuma 16 byte (`EntropyCoreV1!\x00\x00`).
2. **Operand shift-nya bukan register.** Opcode `ROL`/`SHL`/`SHR`/`ROR` menerima jumlah shift sebagai *byte operand ketiga secara literal* di bytecode, bukan nilai dari register yang ditunjuknya. Salah membaca ini membuat setiap shift meleset, dan solvernya tidak menemukan input yang memenuhi.

Posisi 0 punya banyak byte input yang semuanya mengenai target cipher byte; pencarian greedy first-match macet setelah ~9 iterasi.

## Eksploitasi / Solusi

**Depth-first backtracking search yang memprioritaskan ASCII printable** langsung berjalan menuju flag yang unik.

```
THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
```

## Catatan / Insight

**Pelajaran untuk defender:** VM bytecode custom memang bisa di-reverse-engineer, tapi *mahal secara waktu* untuk direverse. Ongkos defensifnya cuma satu hari-kerja developer. Ongkos ofensifnya berhari-hari lebih banyak. Di tempat asimetri ini berharga (DRM, anti-cheat, verifikasi lisensi), VM tetap layer yang layak dipakai; di tempat asimetri itu tidak berharga (crackme offline), VM cuma hiasan.

## Flag

```
THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
```
