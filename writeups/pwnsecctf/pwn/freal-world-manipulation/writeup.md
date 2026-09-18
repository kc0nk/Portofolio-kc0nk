# Freal World Manipulation

## 2.1. Informasi Challenge

| Properti | Nilai |
|---|---|
| Kategori | PWN |
| Kesulitan | Medium |
| Binary | `freal` |
| Arsitektur | x86-64 |
| Proteksi | PIE, Full RELRO, NX, Canary |
| Teknik | OOB → Arbitrary R/W → ROP |

Flag:

```text
pwnsec{34910c7c74c2525b}
```

---

## 2.2. Proteksi Binary

Binary adalah ELF x86-64 PIE.

Proteksi yang terdeteksi:

```text
PIE           aktif
Full RELRO    aktif
NX            aktif
Canary        aktif
```

Jadi exploit tidak bisa menggunakan metode klasik seperti:

```text
overwrite GOT langsung
```

atau stack shellcode.

Kita membutuhkan memory disclosure dan akhirnya ROP.

---

## 2.3. PIE Leak melalui `__dso_handle`

Offset penting:

```text
decimal       = 0x5060
__dso_handle  = 0x5008
puts@GOT      = 0x4f40
ret           = 0x101a
pop rdi; ret  = 0x14cf
```

Fungsi `view()` mempunyai validasi index yang ternyata dapat dibypass menggunakan index negatif.

Index:

```text
-11
```

memilih lokasi yang berkaitan dengan:

```text
__dso_handle
```

`__dso_handle` mempunyai self-reference.

Ketika nilai tersebut dicetak, address yang terlihat adalah:

```text
PIE + 0x5008
```

Maka:

```text
PIE = leaked_address - 0x5008
```

---

## 2.4. Bug pada Allocation Accounting

Fungsi `calibrated()` memeriksa total allocation yang sudah dibulatkan ke page.

Threshold-nya:

```text
0x1fffffff
```

atau sedikit di atas 512 MiB.

Solver membuat allocation besar:

```text
0x800000 = 8 MiB
```

Sebanyak 65 allocation menghasilkan sekitar:

```text
65 × 8 MiB = 520 MiB
```

yang melewati threshold.

---

## 2.5. Memicu Floating-Point Overflow

Solver mengisi dua slot:

```text
1e308
1e308
```

Kemudian melakukan:

```text
multiply(slot2, slot3)
```

dengan rounding:

```text
up
```

Hasil matematis:

```text
1e308 × 1e308 = ∞
```

Kelemahan terdapat pada urutan pengecekan exception.

Program memeriksa floating-point exception sebelum operasi multiplication benar-benar selesai.

Akibatnya status overflow yang tidak semestinya dapat digunakan untuk memperluas batas index.

Dengan kata lain:

```text
floating-point overflow
        ↓
calibrated()
        ↓
index limit membesar
        ↓
OOB access
```

---

## 2.6. Membuat Allocation Berdekatan

Sebelum membuat allocation besar, solver membebaskan allocation awal 8 MiB:

```text
add(0x800000)
destroy(0)
```

Hal ini memengaruhi dynamic mmap threshold glibc.

Kemudian 65 allocation baru dibuat.

Akibatnya allocation besar cenderung berada dalam mapping yang berdekatan.

Secara visual:

```text
[8 MiB][8 MiB][8 MiB][8 MiB]...
```

Exploit membutuhkan salah satu chunk tersebut untuk dapat ditemukan melalui OOB.

---

## 2.7. Pattern Spray

Satu allocation diisi dengan:

```python
p64(decimal) * (...)
```

di mana:

```text
decimal = PIE + 0x5060
```

Karena allocation berukuran 8 MiB, setiap lokasi berisi pointer yang sama:

```text
PIE+0x5060
PIE+0x5060
PIE+0x5060
...
```

Solver kemudian melakukan scan setiap:

```text
0x800000
```

sampai menemukan allocation tersebut.

Ketika pointer tersebut dereference sebagai slot internal, hasilnya menunjuk ke object:

```text
decimal
```

---

## 2.8. Mengubah OOB Menjadi Arbitrary Read/Write

Setelah OOB index ditemukan, exploit dapat memodifikasi slot 0.

Slot tersebut dikontrol melalui struktur:

```text
pointer
usable size
```

Dengan mengubah pointer menjadi:

```text
target address
```

kita mendapatkan:

```text
view(0)
```

sebagai arbitrary read.

Dan:

```text
load(0, data)
```

sebagai arbitrary write.

Primitive akhir:

```text
arbitrary_read(address, size)
arbitrary_write(address, data)
```

---

## 2.9. Leak libc

Karena binary menggunakan libc, exploit membaca:

```text
puts@GOT
```

dengan:

```text
PIE + 0x4f40
```

Hasilnya adalah address `puts` di libc.

Kemudian solver berjalan mundur berdasarkan page:

```text
address & ~0xfff
```

sampai menemukan:

```text
\x7fELF
```

Ini memberikan base address libc.

---

## 2.10. Tidak Bergantung pada libc File Lokal

Menariknya, solver tidak membutuhkan libc yang diberikan secara lokal.

Setelah libc base ditemukan, solver membaca ELF langsung dari memory remote.

Ia membaca:

```text
ELF header
Program Header Table
PT_DYNAMIC
DT_STRTAB
DT_SYMTAB
DT_GNU_HASH
```

Kemudian mencari symbol menggunakan GNU hash.

Dengan demikian solver dapat menemukan:

```text
system
__environ
```

langsung dari libc remote.

---

## 2.11. Leak Stack melalui `__environ`

Symbol:

```text
__environ
```

memberikan pointer menuju environment vector yang berada di stack.

Dengan:

```text
stack_pointer = *__environ
```

solver memperoleh lokasi stack.

Ini penting karena target akhir adalah saved return address pada stack.

---

## 2.12. Mencari Saved Return Address

Solver melakukan scan area stack.

Ia mencari pola:

```text
[self pointer]
[menu choice]
...
[saved return address]
```

Kondisi penting yang digunakan:

```text
[self_pointer == slot + 8]
```

dan saved return address berada di range libc.

Dengan invariant tersebut solver dapat menemukan frame `main` tanpa membutuhkan offset stack yang hardcoded secara absolut.

---

## 2.13. ROP Chain

Setelah saved return address diketahui, solver menulis:

```text
ret
pop rdi; ret
command
system
```

Secara konsep:

```text
saved RIP
    ↓
ret
    ↓
pop rdi; ret
    ↓
alamat command
    ↓
system(command)
```

Command disimpan pada memory writable PIE:

```text
cat /home/ctf/flag-*.txt
```

Karena nama flag memiliki suffix acak, wildcard digunakan:

```text
flag-*.txt
```

---

## 2.14. Alur Exploit Lengkap

```text
negative index
      ↓
PIE leak
      ↓
large allocations
      ↓
floating-point overflow
      ↓
OOB index
      ↓
patterned heap
      ↓
arbitrary read/write
      ↓
puts@GOT
      ↓
libc base
      ↓
GNU hash resolution
      ↓
system + __environ
      ↓
stack leak
      ↓
saved RIP
      ↓
ROP
      ↓
system("cat /home/ctf/flag-*.txt")
      ↓
FLAG
```

---

## 2.15. Solver

File utama:

```text
Freal World Manipulation/solve.py
```

Jalankan:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

Solver mengerjakan seluruh chain secara otomatis:

1. PIE leak
2. allocation calibration
3. OOB search
4. arbitrary read/write
5. libc discovery
6. GNU hash parsing
7. stack leak
8. ROP
9. flag extraction

---

## 2.16. Flag

```text
pwnsec{34910c7c74c2525b}
```

---
