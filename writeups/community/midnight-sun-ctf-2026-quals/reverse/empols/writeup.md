---
ctf: "Midnight Sun CTF 2026 Quals"
kategori: "Reverse Engineering / Misc"
challenge: "empols"
flag: "midnight{y0u_4r3_th3_m4st3r_0f_sl0ps0lv3s}"
teknik: "Server memberikan 20 ELF x86-64 hasil generate acak dari 3 template; deteksi template dengan radare2 lalu ekstrak jawaban otomatis lewat static analysis"
sumber: "https://github.com/Abdelkad3r/midnight-sun-ctf-2026-quals/tree/main/empols"
---

# empols — Midnight Sun CTF 2026 Quals (Reverse Engineering / Automation)

**Info soal:** Hard, target Linux x86-64.

## Deskripsi Singkat

`empols` adalah jenis soal yang menghukum siapa pun yang mencoba menyelesaikan binary secara manual satu per satu. Server memberikan **dua puluh ELF x86-64 baru hasil generate acak** dalam satu sesi dan meminta string input yang memvalidasi masing-masing binary — dan hampir pasti kamu tidak bisa me-reverse-engineer dua puluh binary unik cukup cepat untuk muat dalam batas waktu sesi. Jalur yang dimaksud adalah menyadari bahwa binary-binary ini dihasilkan dari sekumpulan kecil *template*, lalu menulis mesin static-analysis yang mendeteksi template-nya dan mengekstrak jawaban dari hasil disassembly.

```text
$ nc empols.play.ctf.se 3337
```

Servisnya mengeluarkan 20 ELF Linux x86-64 yang di-gzip lalu di-hex-encode satu per satu, dan meminta input yang membuat masing-masing binary tervalidasi. Semua 20 harus benar dalam satu sesi untuk mendapat flag — satu jawaban salah saja koneksinya langsung putus.

Pendekatan naif (`r2` tiap binary secara manual) tidak akan muat dalam batas waktu sesi. Pendekatan yang dimaksud adalah menyadari bahwa binary-binary ini dihasilkan dari set template tetap dan mengotomasi ekstraksinya.

## Recon — Menemukan Template

Men-disassemble beberapa sampel dengan radare2 (`r2 -q -c 'aaaa; pdf @ main' ./bin`) memunculkan tiga pola yang berulang.

### Template 1 — `xor_loop`

```c
char buf[10];
memcpy(buf, hardcoded_bytes, 10);
for (int i = 0; i < 10; i++)
    buf[i] ^= K;                       // K adalah konstanta satu-byte
if (strcmp(input, buf) == 0) win();
```

Input yang valid adalah `hardcoded_bytes[i] ^ K`. Dua hal yang perlu diekstrak:

- Array byte dari penulisan stack `mov byte [rbp - 0xNN], 0xXX` — diurutkan berdasarkan offset stack **menurun** (offset terbesar = byte pertama di stack).
- Konstanta XOR dari `xor (eax|al), 0xNN`.

### Template 2 — `memcpy_strcmp`

```c
char target[] = "some_literal_string";
memcpy(buf, target, sizeof(target));
if (strcmp(input, buf) == 0) win();
```

Input yang valid secara harfiah adalah string yang tertanam. Ambil dari komentar `lea rX, [str.xxx] ; "..."` yang ditempelkan radare2 pada situs panggilan `memcpy`. Fallback: string yang bisa dicetak (printable) terpanjang di output `iz`.

### Template 3 — `paired_word_add`

```c
int16_t first[N], second[N];   // keduanya tertanam sebagai konstanta word
for (int i = 0; i < N; i++) {
    int16_t v = ((int16_t)input[2*i+1]) | (input[2*i] << 8);
    if ((v + first[i]) & 0xFFFF != second[i]) fail();
}
win();
```

Untuk setiap pasangan `(input[2i], input[2i+1])` kita butuh `v = (second[i] - first[i]) mod 2^16`. Bagian menariknya: proses build mengemas byte rendah dari `v` lewat mov yang melakukan sign-extending, jadi:

- `lo = diff & 0xFF` menjadi `input[2*i+1]`
- `hi = (diff >> 8) & 0xFF` menjadi `input[2*i]`

…**kecuali** kalau `lo` punya bit tertinggi yang set, dalam hal ini `hi` harus `0xFF` supaya sign extension-nya tepat. Kalau constraint ini tidak mungkin dipenuhi, posisi input tersebut tidak terkendala dan byte printable apa pun bisa dipakai.

## Analisis — Mesin Static-Analysis

Intinya ada di `extract_answer.py` — beberapa ratus baris eksekusi `r2 -q -c "..."`, pencocokan pola regex terhadap disassembly, dan solver per-template. Bagian-bagian menariknya:

### Deteksi

```python
def detect_template(asm):
    has_xor    = bool(re.search(r"xor\s+(?:eax|al),\s+0x[0-9a-fA-F]+", asm))
    has_memcpy = "sym.imp.memcpy" in asm
    has_strcmp = "sym.imp.strcmp" in asm
    has_shl_8  = bool(re.search(r"shl\s+eax,\s+(?:0x)?8\b", asm))
    has_word_const = bool(re.search(r"mov\s+word\s+\[.*?\],\s+\S", asm))

    if has_memcpy and has_strcmp:         return "memcpy_strcmp"
    if has_word_const and has_shl_8:      return "paired_word_add"
    if has_xor:                            return "xor_loop"
    return "unknown"
```

Urutannya penting — `memcpy_strcmp` diperiksa lebih dulu karena signature-nya paling spesifik; `xor_loop` menjadi fallback penampung semua kasus lainnya.

### Solver xor-loop

```python
def solve_xor_loop(asm):
    xors = find_all_xor_constants(asm)
    K = Counter(xors).most_common(1)[0][0]   # modus mengalahkan noise dari compiler
    consts = find_byte_constants(asm)        # diurutkan berdasarkan offset stack menurun
    return bytes(c ^ K for c in consts).decode("latin-1")
```

Trik "konstanta XOR yang paling sering muncul" menangani kasus di mana compiler menerbitkan instruksi idiom-nol ekstra `xor eax, eax` yang mengotori daftar kandidat.

### Solver memcpy-strcmp

```python
def solve_memcpy_strcmp(path, asm):
    m = re.search(r"lea\s+r[a-z]+,\s+\[[^\]]+\]\s*;\s*0x[0-9a-fA-F]+\s*;\s*\"([^\"]+)\"", asm)
    if m:
        return m.group(1)
    # fallback: string .rodata terpanjang
    return max([s for s in get_strings(path) if len(s) >= 10], key=len)
```

### Solver paired-word-add

Ini yang paling sulit. Ada dua komplikasi yang ditemui:

**Bug 1: `xor al, 0xNN` vs `xor eax, 0xNN`.** Regex XOR pertama hanya cocok dengan `eax`. Radare2 kadang menerbitkan bentuk register byte untuk operasi yang sama tergantung konteks sekitarnya. Diperbaiki dengan `(?:eax|al)`.

**Bug 2: immediate berlabel reloc.** Ketika sebuah immediate konstanta word kebetulan cocok dengan alamat yang dikenal, radare2 me-rename-nya menjadi `reloc.some_symbol` dan nilai literalnya hanya muncul di komentar inline `; 0xNNNN`. Regex immediate langsung tidak mengembalikan apa-apa. Diperbaiki dengan menambahkan *jalur ekstraksi komentar* yang mencoba komentar dulu, baru fallback ke immediate langsung.

Deteksi "dua array dari satu stack frame yang sama" memakai *offset akses loop* (`word [rbp + rax*2 - 0xNN]`) untuk mencari tahu di mana `first[]` berakhir dan `second[]` dimulai:

```python
def find_paired_arrays_from_bases(asm):
    bases = find_paired_array_bases(asm)            # dua offset loop yang berbeda
    base_first, base_second = bases                  # base_first > base_second
    by_off = find_word_constants_dict(asm)
    n = (base_first - base_second) // 2              # jumlah elemen di antara keduanya
    first  = [by_off[base_first  - 2*i] for i in range(n)]
    second = [by_off[base_second - 2*i] for i in range(n)]
    return first, second
```

## Eksploitasi / Solusi

`solve_all.py` terhubung ke servis, mem-parsing setiap blok `BINARY i/20: <hex>`, meng-gunzip, menulis ke file sementara, memanggil `extract_answer.solve()`, mengirim jawabannya, lalu mengulangi:

```bash
$ python3 solve_all.py
[1/20]  'memcpy_strcmp asm-quoted': 'kvBNjJzULfvgwQGl'
[2/20]  'xor_loop K=0x37 N=10':     'BcmoUjthrz'
[3/20]  'paired_word_add N=8 pairs': 'XQjzZvLpdmqRnsKa'
...
[20/20] 'memcpy_strcmp asm-quoted': 'rPmDqWNxJVtFcBhz'
---- final ----
midnight{y0u_4r3_th3_m4st3r_0f_sl0ps0lv3s}
```

Semua 20 terselesaikan kurang dari satu menit.

## Catatan / Insight

Flagnya terbaca "you are the master of slopsolves" — pengakuan sarkastik atas teknik yang persis dipakai: bukan reverse engineering per-binary yang hati-hati, tapi static analysis pencocokan-pola massal ("sloppy" dalam artian memangkas jalur kerja biasa).

**Pelajaran:**

1. **Soal CTF multi-binary sebenarnya adalah soal template yang menyamar.** Kalau sebuah servis memberimu 20+ binary dalam satu sesi, jangan coba selesaikan satu per satu. Identifikasi generator template-nya, tulis extractor-nya, lalu biarkan berjalan.
2. **Scripting radare2 lebih cepat dari pipeline IDA lengkap untuk pekerjaan semacam ini.** `r2 -q -c 'aaaa; pdf @ main' ./bin` menghasilkan output bersih yang mudah di-parse dalam hitungan milidetik. Seluruh driver-nya muat dalam beberapa ratus baris Python tanpa dependency non-stdlib (kecuali `r2` di `$PATH`).
3. **Regex terhadap disassembly rapuh karena dua alasan spesifik** — varian bentuk register (`eax` vs `al`, `rdi` vs `edi`) dan immediate berlabel (radare me-rename literal jadi `reloc.X`). Rencanakan untuk keduanya dengan alternasi gaya `(?:eax|al)` dan pola fallback komentar.
4. **Urutan pengurutan offset stack itu penting.** Saat mengekstrak array byte dari penulisan `mov byte [rbp - 0xNN], val`, byte pertama dari array in-memory hidup di offset negatif *terbesar* (paling dekat dengan `rbp`). Urutkan menurun berdasarkan `0xNN` sebelum di-XOR atau digabungkan. Pernah salah sekali soal ini.
5. **Aritmetika modular 16-bit dengan byte rendah sign-extended** adalah trik template yang berulang. Cek `(v + first[i]) & 0xFFFF == second[i]` secara matematis adalah `v = second - first mod 2^16`, tapi *encoding* `v` dari byte input itu penting karena sign extension pada byte rendah memaksa `hi == 0xFF` ketika `lo >= 0x80`. Selalu tuliskan operasi level-byte yang sebenarnya dilakukan binary sebelum berasumsi inversnya sekadar pengurangan sederhana.

## Flag

```
midnight{y0u_4r3_th3_m4st3r_0f_sl0ps0lv3s}
```
