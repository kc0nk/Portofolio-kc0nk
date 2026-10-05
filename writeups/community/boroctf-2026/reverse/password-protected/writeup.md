---
ctf: "boroCTF 2026"
kategori: "Reverse Engineering"
challenge: "password_protected"
flag: "boroCTF{I_H8_M@7ing_StR1ng5_cHals}"
teknik: "movabsq password tersusun + loop deobfuskasi XOR-7 di ELF stripped; gerbang strcmp cuma dekorasi"
sumber: "https://github.com/Abdelkad3r/boroCTF-2026"
---

# password_protected — boroCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Sebuah ELF Linux 64-bit yang sudah di-strip (PIE, hasil kompilasi GCC 13.3) yang meminta password. Kalau benar, program mencetak pesan sukses + flag; kalau salah, mencetak `My disappointment is immeasurable.`

## Recon

Menjalankan `strings` langsung memunculkan empat potongan teks berukuran 8-byte yang terlihat seperti password tertanam:

```
$ strings password_protected | grep -E 'Rate|Beca|reat|allenge'
Rate5Sta
Becauseg
reatChal
allenge
```

Panjang yang persis 8 byte ini adalah petunjuk kuncinya. Potongan 8-byte adalah bentuk alami dari immediate `movabsq` di x86-64, dan `objdump -d` mengonfirmasi bahwa binary menyusun password di stack sepotong 8-byte demi 8-byte, memanggil `strlen()` di antara tiap penulisan untuk menentukan posisi potongan berikutnya di akhir buffer yang sedang bertambah:

| alamat | bytes | hasil buffer |
|---|---|---|
| `0x1336` | `0x6174533565746152` ("Rate5Sta") | `Rate5Sta` |
| `0x1340` | `0x7372` ("rs") | `Rate5Stars` |
| `0x1459` | `0x4765737561636542` ("BecauseG") | `…BecauseG` |
| `0x1463` | `0x6c61684374616572` ("reatChal") | `…reatChal` |
| `0x1474` | `0x65676e656c6c61` ("allenge\0") | `…allenge` |

Buffer hasil rekonstruksi adalah `Rate5StarsBecauseGreatChallenge`. `strcmp` di `0x1496` adalah satu-satunya gerbang, dan `jne` di `0x149d` adalah satu-satunya percabangan yang membelot dari jalur sukses.

## Analisis — Bagian yang Sebenarnya Penting

Flag **bukan** password itu sendiri. Flag adalah apa yang dicetak oleh jalur sukses. Antara `0x1248` dan `0x132f`, fungsi `main` menginisialisasi buffer 34-byte di `-0x1a0(%rbp)` satu `movb` demi satu `movb`. Begitu `strcmp` berhasil, sebuah loop di `0x14ba..0x1503` menelusuri buffer tersebut, meng-XOR setiap byte dengan `0x7`, lalu memanggil `putchar`. Flag **tidak pernah** muncul sebagai plaintext di dalam binary.

## Eksploitasi / Solusi

Karena data yang dibutuhkan (34 byte terobfuskasi) sudah bisa dibaca langsung dari hasil disassembly, kita tidak perlu menjalankan binary sama sekali — cukup ambil byte-nya dan XOR dengan `0x7`:

```python
buf = [0x65,0x68,0x75,0x68,0x44,0x53,0x41,0x7c,0x4e,0x58,0x4f,0x3f,0x58,
       0x4a,0x47,0x30,0x6e,0x69,0x60,0x58,0x54,0x73,0x55,0x36,0x69,0x60,
       0x32,0x58,0x64,0x4f,0x66,0x6b,0x74,0x7a]
print(''.join(chr(b ^ 0x7) for b in buf))
# boroCTF{I_H8_M@7ing_StR1ng5_cHals}
```

## Catatan / Insight

Flag itu sendiri adalah lelucon dari pembuat soal: "I hate matching strings challenges" (aku benci soal cocok-cocokan string) adalah komentar sarkastik terhadap gerbang `strcmp` yang di permukaan terlihat seperti inti soal ini — padahal gerbang itu cuma dekorasi, dan flag sebenarnya bersembunyi di loop XOR setelahnya.

**Pelajaran umum:** jangan percaya pada "wrapper" (prompt soal, UI, hal yang terlihat jelas) — baca artefaknya (bytes, disassembly) langsung. `strcmp` di sini terlihat seperti gerbang utama, padahal cabang itu hanya memicu loop reveal XOR-7 di atas buffer 34-byte yang sudah dipanggang sebelumnya.

## Flag

```
boroCTF{I_H8_M@7ing_StR1ng5_cHals}
```
