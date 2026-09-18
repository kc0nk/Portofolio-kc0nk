# Death Ops

## 3.1. Informasi Challenge

| Properti | Nilai |
|---|---|
| Kategori | PWN / Kernel |
| Kesulitan | Medium |
| Target | Linux 4.9.333 |
| Teknik | Kernel arbitrary write, KASLR leak, `core_pattern` |
| Flag | `pwnsec{527916de221fe1c8}` |

Challenge ini berbeda dari dua challenge sebelumnya karena exploit berjalan sampai level kernel.

---

## 3.2. Komponen Challenge

Archive berisi:

```text
bzImage
rootfs.cpio.gz
Dockerfile
run-qemu.sh
blackops
shadowops.ko
```

Kernel:

```text
Linux 4.9.333
```

Binary utama:

```text
blackops
```

dan kernel module:

```text
shadowops.ko
```

---

## 3.3. Seccomp Alphanumeric

Input payload dibatasi hanya karakter alphanumeric.

Setelah payload masuk, seccomp hanya mengizinkan:

```text
read
write
exit
exit_group
```

Jadi shellcode normal tidak dapat dikirim secara langsung.

Solver menggunakan alphanumeric decoder ALPHA3.

Stage pertama sangat kecil dan hanya bertugas memuat stage berikutnya.

Konsepnya:

```text
alphanumeric stage
       ↓
decoder
       ↓
stage 2
       ↓
kernel exploitation stage
```

---

## 3.4. Vulnerability pada `shadowops.ko`

Module menyediakan interface:

```text
/dev/shadowops
```

dan fungsi `shadowops_write`.

Input 16 byte berbentuk:

```c
struct {
    uint64_t target;
    uint64_t value;
};
```

Primitive tersebut pada dasarnya melakukan:

```c
*(uint64_t *)target = value;
```

Ini adalah arbitrary 8-byte kernel write.

Namun terdapat counter:

```text
used
```

yang membatasi operasi menjadi dua kali.

Sekilas terlihat seperti mitigasi.

Namun counter tersebut sendiri berada di memory module yang dapat ditulis oleh primitive.

---

## 3.5. Lokasi Module

Melalui:

```text
/proc/modules
```

alamat module dapat diketahui.

Output memiliki format seperti:

```text
shadowops ... Live 0xffffffffc........
```

Address tersebut merupakan module base.

Jadi:

```text
module_base = leaked address
```

Layout module yang dipakai solver:

```text
.text  = base
.data  = base + 0xc80
.bss   = base + 0xcd0
```

Counter:

```text
used = base + 0xcd0
```

---

## 3.6. Reset Limit Dua Kali

Karena `used` berada pada:

```text
base + 0xcd0
```

kita dapat melakukan write:

```text
*(uint64_t *)(base + 0xcd0) = 0
```

Setiap kali counter hampir habis, reset kembali:

```text
used = 0
```

Dengan demikian batas dua write tidak lagi menjadi hambatan.

Ini merupakan pola vulnerability yang penting:

> Membatasi jumlah operasi tidak efektif apabila state yang menyimpan counter juga dapat dimodifikasi oleh primitive yang sama.

---

## 3.7. Menanam Primitive Baru di `.text`

Bagian `.text` module ternyata writable pada environment challenge.

Solver menggunakan area yang tidak digunakan pada:

```text
shadowops_open
shadowops_release
```

untuk menanam primitive sekitar 30 byte.

Primitive baru mempunyai dua mode.

### Mode `count == 8`

Melakukan read:

```text
kernel_address → user buffer
```

### Mode `count == 16`

Mempertahankan behavior write:

```text
{target, value}
```

Dengan demikian arbitrary write awal berubah menjadi:

```text
arbitrary read + arbitrary write
```

---

## 3.8. Mengubah Entry `shadowops_write`

Fungsi asli:

```text
shadowops_write
```

berada pada:

```text
module_base + 0x30
```

Entry tersebut kemudian dipatch agar melompat ke primitive baru.

Konsep:

```text
shadowops_write
      ↓
jmp module_base
      ↓
custom read/write primitive
```

---

## 3.9. Kernel KASLR Leak

Setelah arbitrary read tersedia, solver membaca instruction pada:

```text
shadowops_write + 0x57
```

Instruction tersebut berupa:

```text
e8 disp32
```

yang merupakan relative `call`.

Target call adalah:

```text
_copy_from_user
```

Dengan relocation module, address aktual dapat dihitung:

```text
copy_from_user
    =
module_base
+ offset_instruction
+ sign_extend(disp32)
```

Solver mengetahui address dasar kernel `copy_from_user`:

```text
0xffffffff81371700
```

Sehingga KASLR slide:

```text
slide = actual_copy_from_user
      - 0xffffffff81371700
```

---

## 3.10. Menghitung `core_pattern`

Setelah KASLR slide diperoleh, address:

```text
core_pattern
```

dapat dihitung:

```text
core_pattern =
0xffffffff820674e0 + slide
```

Target ini berada di writable kernel data.

---

## 3.11. Mengapa `core_pattern` Menarik?

Linux dapat menggunakan pipe pada:

```text
core_pattern
```

Jika nilainya dimulai dengan:

```text
|
```

kernel akan menjalankan program helper ketika terjadi core dump.

Exploit menulis:

```text
|/bin/sh -c cat${IFS}/flag*${IFS}>/dev/console
```

Keuntungan menggunakan:

```text
${IFS}
```

adalah command tetap dapat dipisahkan dengan benar oleh shell walaupun argument splitting pada core helper tidak bekerja seperti command line biasa.

---

## 3.12. Trigger Core Dump

Setelah `core_pattern` ditimpa, user-space process sengaja dibuat crash.

Contoh konsep:

```c
*(volatile uint64_t *)0 = 0;
```

atau dereference NULL.

Kernel kemudian mengikuti:

```text
core_pattern
```

dan menjalankan:

```text
/bin/sh
```

sebagai usermode helper dengan privilege yang sesuai.

Command akhirnya:

```text
cat /flag*
```

dan output diarahkan ke:

```text
/dev/console
```

---

## 3.13. Mengapa Seccomp Tidak Menghentikannya?

Seccomp membatasi syscall process exploit.

Tetapi jalur:

```text
signal
   ↓
kernel core dump
   ↓
piped core helper
   ↓
/bin/sh
```

adalah jalur yang diproses kernel.

Jadi membatasi syscall process awal tidak otomatis menghentikan command yang dijalankan kernel sebagai bagian dari mekanisme core dump.

Ini merupakan pelajaran penting dalam kernel exploitation:

> Jangan hanya melihat syscall yang tersedia bagi proses. Analisis juga mekanisme kernel yang dapat memicu execution di luar konteks syscall biasa.

---

## 3.14. Failed Approaches

Beberapa pendekatan yang dicoba tetapi gagal.

### A. Menimpa `sys_call_table`

Tidak berhasil karena mapping tersebut read-only.

```text
sys_call_table
      ↓
write
      ↓
page fault
```

### B. Fake LSM Hook

Eksperimen dengan LSM hook yang memanggil payload user-space gagal karena instruction fetch dari user address tidak dapat dilakukan pada konteks kernel yang diharapkan.

KPTI/NX ikut berpengaruh.

### C. `SIDT`

Address yang diperoleh dari:

```text
SIDT
```

tidak memberikan KASLR slide yang berguna karena nilai tersebut tidak mengikuti randomization kernel seperti yang dibutuhkan.

---

## 3.15. Alur Exploit Lengkap

```text
/proc/modules
      ↓
module base leak
      ↓
alphanumeric decoder
      ↓
kernel arbitrary write
      ↓
reset used counter
      ↓
patch module .text
      ↓
arbitrary read
      ↓
read relocated call
      ↓
copy_from_user address
      ↓
kernel KASLR slide
      ↓
core_pattern address
      ↓
overwrite core_pattern
      ↓
trigger crash
      ↓
kernel executes pipe helper
      ↓
/bin/sh
      ↓
cat flag
      ↓
FLAG
```

---

## 3.16. Solver

File:

```text
Death Ops/solve.py
```

Solver melakukan:

1. koneksi ke challenge
2. membaca `/proc/modules`
3. mengambil module base
4. mengirim alphanumeric loader
5. menanam kernel read/write primitive
6. mereset counter
7. membaca relocated instruction
8. menghitung KASLR slide
9. menghitung `core_pattern`
10. menulis shell command
11. trigger core dump
12. membaca flag

Jalankan:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

---

## 3.17. Flag

```text
pwnsec{527916de221fe1c8}
```

---

# Perbandingan Teknik

Ketiga challenge mempunyai primitive awal yang berbeda, tetapi pola exploitation-nya serupa.

| Tahap | PHP Sandbox | Freal | Death Ops |
|---|---|---|---|
| Initial bug | PHP serialization UAF | OOB index | Kernel arbitrary write |
| Leak | Heap/object | PIE/libc/stack | Module/kernel |
| Primitive | Arbitrary read | Arbitrary R/W | Arbitrary kernel R/W |
| Target akhir | `system` handler | `system` + ROP | `core_pattern` |
| Execution | Fake Closure | Saved RIP | Kernel usermode helper |
| Mitigasi yang dibypass | `disable_functions` | PIE/RELRO/NX | seccomp/KASLR |
| Final | `/readflag` | `system("cat ...")` | `/bin/sh -c cat ...` |

---

# Pelajaran Penting

## 1. Mitigasi yang berdiri sendiri belum tentu menjadi boundary keamanan

Pada PHP:

```text
disable_functions
```

tidak cukup karena handler internal masih berada di memory.

Pada Death Ops:

```text
seccomp
```

tidak cukup untuk menghentikan kernel-driven execution path.

Pada Freal:

```text
Full RELRO
```

tidak mencegah exploit apabila kita sudah mendapatkan arbitrary write ke memory lain.

---

## 2. Information leak sering menjadi kunci

Ketiga exploit membutuhkan address disclosure:

```text
PHP       → heap/object addresses
Freal     → PIE → libc → stack
Death Ops → module → kernel KASLR
```

Setelah address diketahui, mitigasi randomization menjadi jauh lebih lemah.

---

## 3. Counter hanya efektif jika state-nya benar-benar terlindungi

Death Ops memberikan contoh jelas:

```text
primitive = arbitrary write
counter   = writable
```

Maka:

```text
counter limit ≠ security boundary
```

---

## 4. Parsing struktur internal dapat menggantikan file lokal

Pada Freal, solver tidak mengandalkan libc lokal.

Ia membaca:

```text
ELF header
PT_DYNAMIC
GNU hash
symbol table
string table
```

langsung dari remote memory.

Teknik ini membuat exploit lebih fleksibel terhadap variasi libc.

---

## 5. Struktur internal runtime sangat penting pada memory corruption

PHP Sandbox Escape menunjukkan bahwa exploit modern tidak selalu berupa:

```text
buffer overflow
```

Sebaliknya, pemahaman terhadap:

```text
zval
zend_object
HashTable
zend_function_entry
zend_closure
executor_globals
```

dapat menghasilkan primitive yang jauh lebih kuat.

---

# Struktur File dalam Arsip

Struktur utama yang relevan:

```text
pwn/
├── PHP Sandbox Escape/
│   ├── challenge/
│   ├── analysis/
│   │   ├── exploit.php
│   │   ├── spl-uaf-leak.php
│   │   └── ...
│   ├── solve.py
│   ├── instance.json
│   ├── flag
│   └── writeup/
│       ├── en.md
│       └── ko.md
│
├── Freal World Manipulation/
│   ├── challenge/
│   ├── analysis/
│   │   ├── evidence.md
│   │   └── probe_maps.sh
│   ├── solve.py
│   ├── instance.json
│   ├── flag
│   └── writeup/
│       ├── en.md
│       └── ko.md
│
└── Death Ops/
    ├── challenge/
    ├── analysis/
    ├── solve.py
    ├── instance.json
    ├── flag
    └── writeup/
        ├── en.md
        └── ko.md
```

---

# Daftar Flag

### PHP Sandbox Escape

```text
pwnsec{5dbe4132b1294725}
```

### Freal World Manipulation

```text
pwnsec{34910c7c74c2525b}
```

### Death Ops

```text
pwnsec{527916de221fe1c8}
```

---

# Kesimpulan

`pwn.zip` berisi tiga challenge dengan tingkat exploitation yang berbeda.

**PHP Sandbox Escape** berfokus pada internals PHP dan bagaimana re-entrant serialization dapat menghasilkan shared `var_hash` UAF. Dari UAF tersebut exploit membangun arbitrary read dan fake Closure untuk memanggil `system`.

**Freal World Manipulation** memanfaatkan kombinasi bug logic, floating-point exception handling, signed index, dan heap layout. Setelah OOB berhasil diperoleh, primitive tersebut berkembang menjadi arbitrary read/write, kemudian digunakan untuk membocorkan PIE, libc, stack, dan melakukan ROP.

**Death Ops** membawa exploitation ke kernel. Primitive arbitrary write pada module dikembangkan menjadi arbitrary read/write, digunakan untuk memperoleh kernel KASLR slide, kemudian `core_pattern` ditimpa untuk mendapatkan eksekusi root melalui piped core dump helper.

Ketiga challenge menunjukkan pola umum exploitation modern:

```text
Bug
 ↓
Memory corruption / primitive
 ↓
Information leak
 ↓
Bypass randomization / mitigation
 ↓
Stronger primitive
 ↓
Control-flow / code execution
 ↓
Flag
```

Dengan memahami pola tersebut, proses solving menjadi lebih sistematis: jangan langsung mencari shellcode atau ROP. Pertama tentukan **primitive apa yang benar-benar tersedia**, kemudian cari **leak yang dapat menghilangkan ketidakpastian address**, lalu tingkatkan primitive tersebut sampai mencapai target eksekusi.
