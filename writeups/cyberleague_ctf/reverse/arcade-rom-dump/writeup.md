# Writeup — Arcade ROM Dump

**Kategori:** Reverse Engineering
**CTF:** CYBERLEAGUE
**Flag:** `CYBERLEAGUE{r0m_prot3ct10n_cr4ck3d}`

---

## 1. Deskripsi Soal

> A garage-sale crate turned up a bare circuit board pulled from a shuttered 90s arcade cabinet — no marquee, no cabinet art, just a single ROM chip and a rumour that it still guards the machine's original unlock code. The collector wired it up long enough to pull one raw dump before the board's power supply died for good. Whatever protected that code decades ago is apparently still doing its job. Dig into the dump and recover the code the chip was built to protect.

Berkas yang diberikan: `arcade-rom-dump.zip` → berisi satu file bernama `arcade_rom`.

---

## 2. Triage Awal

```bash
$ unzip -l arcade-rom-dump.zip
    Length      Date    Time    Name
---------  ---------- -----   ----
    15328  2026-08-26 15:14   arcade_rom

$ file arcade_rom
arcade_rom: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=30f2a2f9b7f2a158108e0bc934e4badbcbb72ac0,
for GNU/Linux 3.2.0, stripped
```

Meski dinamai "ROM dump", berkas ini sebenarnya adalah **ELF64 x86-64 yang di-strip** — bukan citra ROM mentah. Ini petunjuk pertama bahwa "chip proteksi" hanyalah bungkus cerita; targetnya adalah biner Linux biasa.

`strings` memberi beberapa petunjuk penting:

```
CYBERLEAGUE{not_the_real_flag_sorry}      <- umpan (decoy)
ARCADEX Copy-Protection v2.4.1
Integrity check failed. Exiting.
Anomalous execution timing. Aborting.
Reading ROM configuration from %s ...
Protection chip engaged; payload withheld.
Unlock code rejected. Protection chip remains engaged.
/proc/self/status
TracerPid:
Tamper detected.
/opt/arcade/cabinet.cfg
Usage: %s <unlock-code>
```

Dari sini terlihat jelas ada beberapa lapisan anti-analisis:
- anti-debug (`TracerPid`, `ptrace`)
- anti-timing (`clock_gettime`)
- pengecekan file konfigurasi (`fopen("/opt/arcade/cabinet.cfg")`)
- sebuah string flag palsu yang sengaja dipasang untuk menjebak orang yang hanya menjalankan `strings`/`grep`.

---

## 3. Struktur Biner

```bash
$ readelf -h arcade_rom | grep Entry
  Entry point address:               0x401130

$ readelf -S -W arcade_rom
  [14] .text     PROGBITS  0000000000401130  001130  0004ac  AX
  [16] .rodata   PROGBITS  0000000000402000  002000  0001ca  A
  [19] .init_array INIT_ARRAY 0000000000403de8 002de8 000008  WA
  [24] .data     PROGBITS  0000000000404080  003080  000004  WA
```

Biner ini statis-kecil (hanya ~0x4ac byte `.text`), memudahkan disassembly manual dengan `objdump -d -M intel`.

---

## 4. Analisis Alur Program

### 4.1 `main` (di sekitar `0x40126a`)

Alur eksekusi utama:

1. **Cetak banner** — `"ARCADEX Copy-Protection v2.4.1"` dan `"Reading ROM configuration from %s ..."`.
2. **`fork()` + `ptrace(PTRACE_TRACEME, ...)` pada anak proses** (fungsi kecil di `0x4012a9`–`0x4012d7`):
   - Jika `ptrace(PTRACE_TRACEME)` gagal (artinya sudah ada debugger yang menempel), anak keluar dengan `_exit(1)`.
   - Jika berhasil, anak keluar dengan `_exit(0)`.
   - Induk menunggu (`waitpid`) dan memeriksa *exit status* anak lewat `WIFEXITED`/`WEXITSTATUS`. Jika hasilnya bukan `1` (indikasi "sukses ber-ptrace", artinya tidak ada debugger), program lanjut. Jika macet karena sinyal (misal debugger menempel dan mengganggu), dianggap "Integrity check failed."
3. **Cek `/proc/self/status` untuk `TracerPid:`.** Fungsi ini membuka file tersebut, mencari baris yang diawali `"TracerPid:"` dengan `strncmp`, lalu men-parse nilai sesudahnya dengan `strtol`. Jika nilainya bukan 0 (proses sedang di-trace), program mencetak `"Tamper detected."` dan keluar dengan kode 1.
4. **Cek timing eksekusi.** Ambil `clock_gettime(CLOCK_MONOTONIC, ...)`, jalankan loop kosong 10.000 iterasi (`0x2710`), ambil waktu lagi, hitung selisih dalam nanodetik. Jika selisihnya **lebih dari 0x1dcd6500 ns (500 ms)** — artinya ada breakpoint/single-step yang memperlambat eksekusi — program mencetak `"Anomalous execution timing. Aborting."` dan keluar.
5. **Susun buffer kunci di stack, byte demi byte** (`mov BYTE PTR [rsp+0x168], 0x41` … dst.), menghasilkan string ASCII 8 karakter:

   ```
   0x41 0x52 0x43 0x41 0x44 0x45 0x39 0x30  ->  "ARCADE90"
   ```

6. **Validasi argumen (`argv[1]`)**:
   - Cek `argc > 1`, jika tidak: cetak `"Usage: %s <unlock-code>"`.
   - `strlen(argv[1]) == 8` — jika tidak, tolak.
   - `memcmp(argv[1], "ARCADE90", 8)` — jika tidak cocok, cetak `"Unlock code rejected. Protection chip remains engaged."` dan keluar dengan kode 1.
7. **Jika kode cocok** → masuk ke rutin dekripsi payload flag dan `puts()` hasilnya.

### 4.2 Rutin Dekripsi Flag (`0x40154b`–`0x4015d7`)

```asm
lea    rdi,[rsp+0x120]
mov    esi,0x402140          ; alamat blob terenkripsi di .rodata
mov    ecx,0x23              ; 0x23 = 35 byte
rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]   ; salin 35 byte ke stack

; --- tahap 1: ROR 3 bit tiap byte ---
lea    rcx,[rsp+0x120]
lea    rdx,[rsp+0x143]       ; rcx+0x23 -> batas akhir
loop:
ror    BYTE PTR [rax],0x3
add    rax,0x1
cmp    rax,rdx
jne    loop

; --- tahap 2: XOR dengan key[i % 8] ---
mov    esi,0x0                ; i = 0
loop2:
mov    edi,0x8
mov    eax,esi
cdq
idiv   edi                    ; edx = i % 8
movsxd rdx,edx
movzx  eax, BYTE PTR [rsp+rdx*1+0x168]   ; key[i % 8]  ("ARCADE90")
xor    BYTE PTR [rsp+rsi*1+0x120], al
add    rsi,0x1
cmp    rsi,0x23
jne    loop2

; --- tahap 3: swap pasangan byte bertetangga (17 pasang pertama) ---
lea    rsi,[rcx+0x22]          ; batas: rcx + 34
loop3:
movzx  eax, BYTE PTR [rcx]
movzx  edx, BYTE PTR [rcx+0x1]
mov    BYTE PTR [rcx], dl
mov    BYTE PTR [rcx+0x1], al
add    rcx,0x2
cmp    rcx,rsi
jne    loop3

mov    BYTE PTR [rsp+0x143],0x0   ; null-terminate
puts   rdi
```

Ringkas: buffer 35 byte diambil dari `.rodata:0x402140`, lalu:

1. **ROR 3 bit** per byte (`b = (b >> 3) | (b << 5) & 0xFF`)
2. **XOR** dengan `key[i % 8]`, di mana `key = "ARCADE90"` (kunci unlock yang sama dipakai dua kali)
3. **Swap pasangan byte bertetangga**: `(buf[0],buf[1])`, `(buf[2],buf[3])`, … untuk 17 pasang pertama (indeks 0–33). Byte ke-35 (indeks 34) **tidak** ikut ditukar karena jumlah byte ganjil (35).

Hasilnya langsung berupa string flag ASCII yang di-null-terminate dan dicetak dengan `puts`.

### 4.3 Elemen Umpan (Decoy)

- String `CYBERLEAGUE{not_the_real_flag_sorry}` di `.rodata:0x402010` — dicetak oleh fungsi kecil di `0x401257`, tetapi **fungsi ini tidak pernah dipanggil** dari `main`. Ini jebakan untuk orang yang cuma `strings | grep CYBERLEAGUE`.
- Fungsi di `0x401216` melakukan XOR byte-demi-byte dengan nilai yang diturunkan dari `time(NULL)` — juga **tidak pernah dipanggil**. Kemungkinan dipasang untuk mengecoh analis statis yang mengira waktu sistem ikut menjadi bagian kunci dekripsi.

---

## 5. Strategi Reversing

Poin kunci: **semua transformasi kriptografis di sini bersifat statis dan bisa dihitung ulang tanpa menjalankan biner sama sekali.**

1. **Kunci unlock code** (`"ARCADE90"`) tersimpan sebagai immediate byte langsung di instruksi `mov BYTE PTR [...], imm8` — tidak perlu brute-force, tinggal dibaca dari disassembly.
2. **Blob terenkripsi** (35 byte) ada di `.rodata` pada offset tetap (`vaddr 0x402140` = `file offset 0x2000 + (0x402140 - 0x402000)` = `0x2140`), sehingga bisa diambil langsung dari file dengan Python tanpa eksekusi.
3. Karena ketiga operasi (ROR, XOR, swap-pair) semuanya **bijektif dan deterministik**, cukup meniru urutan yang sama persis seperti yang dilakukan biner (ROR → XOR → swap) menggunakan kunci yang sudah diketahui untuk mendapatkan plaintext.
4. **Semua lapisan anti-debug (fork+ptrace, cek TracerPid, cek timing) menjadi tidak relevan** karena solver tidak pernah menjalankan biner — ia hanya membaca byte mentah dari file ELF di disk. Ini adalah pendekatan *pure static* yang otomatis melewati seluruh proteksi run-time.
5. Sebagai validasi tambahan (opsional), biner juga bisa dijalankan langsung dengan argumen `ARCADE90` di lingkungan tanpa debugger untuk mengonfirmasi hasil solver statis — karena tidak ada debugger yang menempel dan tidak ada delay abnormal, ketiga pemeriksaan run-time otomatis lolos.

---

## 6. Solver Script

```python
#!/usr/bin/env python3
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "arcade_rom"
elf = open(path, "rb").read()

def rodata(vaddr, n):                      # .rodata: vaddr 0x402000 <-> offset 0x2000
    off = vaddr - 0x402000 + 0x2000
    return elf[off:off + n]

blob = rodata(0x402140, 0x23)              # 35 byte terenkripsi
key  = b"ARCADE90"

ror3 = lambda b: ((b >> 3) | (b << 5)) & 0xFF

buf = bytearray(ror3(b) for b in blob)                       # 1) ror 3
buf = bytearray(b ^ key[i % 8] for i, b in enumerate(buf))   # 2) xor key[i%8]
for i in range(0, 34, 2):                                    # 3) swap pasangan
    buf[i], buf[i + 1] = buf[i + 1], buf[i]

print(bytes(buf).decode())
```

Jalankan:

```bash
$ python3 solve_arcade_rom.py arcade_rom
CYBERLEAGUE{r0m_prot3ct10n_cr4ck3d}
```

---

## 7. Verifikasi Dinamis

```bash
$ ./arcade_rom ARCADE90
ARCADEX Copy-Protection v2.4.1
Reading ROM configuration from /opt/arcade/cabinet.cfg ...
CYBERLEAGUE{r0m_prot3ct10n_cr4ck3d}
$ echo $?
0

$ ./arcade_rom WRONGKEY
ARCADEX Copy-Protection v2.4.1
Reading ROM configuration from /opt/arcade/cabinet.cfg ...
Unlock code rejected. Protection chip remains engaged.
$ echo $?
1
```

Hasil solver statis cocok dengan output biner saat dijalankan dengan unlock code yang benar.

---

## 8. Kesimpulan

| Aspek | Temuan |
|---|---|
| Jenis proteksi | Anti-debug (fork+ptrace, `/proc/self/status`), anti-timing, decoy string |
| Kunci unlock code | `ARCADE90` (hardcoded, immediate byte di `.text`) |
| Algoritma enkripsi flag | ROR3 → XOR (kunci berulang 8 byte) → swap pasangan byte bertetangga |
| Lokasi ciphertext | `.rodata` @ `0x402140`, 35 byte |
| Pendekatan solve | Static extraction — tidak perlu melewati proteksi run-time sama sekali |
| **Flag** | **`CYBERLEAGUE{r0m_prot3ct10n_cr4ck3d}`** |
