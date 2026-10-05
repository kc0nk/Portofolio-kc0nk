---
ctf: "BhAcKAri CTF 2026"
kategori: "Reverse Engineering"
challenge: "Don't Unpack Me"
flag: "bhackariCTF{7zip_1s_aw3s0m3}"
teknik: "PE 5.632-byte hand-crafted; manual PE loader menambal 4 callback ke PE dalam; CRC32(GetHandlerProperty2 milik 7z.dll v24.09) jadi kunci RC4"
---

# Don't Unpack Me — BhAcKAri CTF 2026 (Reverse Engineering)

## Deskripsi Singkat

```text
$ file dont_unpack_me.exe
PE32+ executable (GUI) x86-64, for MS Windows
$ wc -c dont_unpack_me.exe
5632 dont_unpack_me.exe
```

PE Windows hand-crafted 5.632-byte. Section `.x` adalah blob 2.560-byte yang byte pertamanya `4d 5a 90 00 03 00…` — **PE32+ image lain**. `.text` luar mencurigakan kecil (0x4c2 byte) — sebuah stub, bukan program sungguhan.

## Analisis — Jebakan Intuitif

Gerakan alami adalah mengekstrak PE dalam dari section `.x` dan menjalankannya standalone. Hasilnya *"Not there yet!"*. Flag sungguhan tidak pernah hidup di satu artefak — ia dirakit ulang dari byte yang harus **ditemukan di tempat lain di sistemmu**, makanya ada import literal `findme.dll`.

## Eksploitasi — Perburuan Harta Lima-Layer

**Layer 1 — manual PE loader.** Fungsi entry outer (`0x1400013d0`) melakukan tarian manual-PE-loader kanonik: `GetModuleHandleA(NULL)` → telusuri section mencari `.x` → `VirtualAlloc(MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` → memcpy header+section → resolve import lewat `LoadLibraryA` + `GetProcAddress`.

**Layer 2 — empat patch 8-byte ke fungsi entry dalam.** Gerakan tak biasa: fungsi entry PE dalam punya empat slot 8-byte yang ditimpa outer dengan callback ke `.text` milik *outer sendiri* — jadi PE dalam sengaja dirusak tanpa patch dari outer. Itu sebabnya menjalankan versi "unpacked" jalan buntu.

**Layer 3 — decode nama proc.** Patch #2 (outer `0x140001054`) meng-XOR 19 byte `.rdata` outer dengan 19 byte `.rdata` dalam. Plaintext-nya: **`GetHandlerProperty2`** — export 7-Zip yang terkenal.

**Layer 4 — baca petunjuk versi.** Patch #3 (outer `0x140001000`) memanggil `GetFileVersionInfoA("findme.dll")` dan mengecek `dwFileVersionLS == 0x00180009` — versi file `*.*.24.9`. Itu **7-Zip v24.09** (Nov 2024). Jadi `findme.dll` adalah `7z.dll` versi 24.09 yang di-rename — dan byte flag-nya akan direkonstruksi dari machine code hasil kompilasi `GetHandlerProperty2` di build spesifik itu.

**Layer 5 — dekripsi.** Patch #4 (outer `0x1400010b8`) adalah flag-builder hand-rolled yang menyalin 28 byte dari kode `GetHandlerProperty2` di offset tetap (sebagian pembacaan biasa, sebagian pasangan XOR). PE dalam kemudian menghitung `CRC32(GetHandlerProperty2[0..0x250])` sebagai **kunci RC4 4-byte** dan mendekripsi RC4 28 byte tersebut.

```bash
$ ./solve.py -v
[+] DLL                   = handout/findme.dll
[+] GetHandlerProperty2   = rva=0x77b3c file=0x76f3c
[+] CRC32(fn[..0x250])    = 0x23cd958c
[+] RC4 ciphertext        = 4ea617b13a1b4db37a1ee082216a5202fab3e7e7dfd821e912f2d48f
bhackariCTF{7zip_1s_aw3s0m3}
```

## Catatan / Insight

**Ini adalah ideal platonik dari challenge packer/unpacker.** Penulisnya membangun lima layer indirection di mana output tiap layer adalah kunci layer berikutnya — dan materi keying di layer 3-5 hidup di dalam **DLL pihak ketiga** yang versinya spesifik penting. Pelajaran untuk sisi ofensif: DLL yang di-load secara dinamis di software komoditas (7-Zip, OpenSSL, ICU) adalah artefak biner stabil yang bisa dipatok attacker. Pelajaran untuk sisi defensif: kalau anti-tamper-mu bergantung pada hashing DLL saudara, serangan binary-replacement terhadap DLL itu diam-diam mematahkan rantainya.

## Flag

```
bhackariCTF{7zip_1s_aw3s0m3}
```
