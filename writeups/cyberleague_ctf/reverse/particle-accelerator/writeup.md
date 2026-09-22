# Particle Accelerator — Reverse Engineering Write-Up

> **Category:** Reverse Engineering  
> **Flag format:** `CYBERLEAGUE{...}`  
> **Artifacts:** `calibrator`, `sim_kernel.bin`  
> **Target:** local binary, no remote service

---

## 1. Challenge

The challenge description says:

```text
The physics lab's accelerator has ground to a halt: its calibration subsystem
is rejecting every sequence the technicians feed it, and the postdoc who wrote
the thing graduated two years ago. Recovered from the maintenance terminal are
the control program and the low-level image it loads onto the coprocessor at
startup. Somewhere in their combined logic is the one sequence the accelerator
is waiting for. Find it and get the beam back online.
```

The archive contains:

```text
calibrator
sim_kernel.bin
```

The intended approach is static analysis of the host binary and recovery of the sequence accepted by its validator.

---

# 2. Initial Triage

Extract the challenge:

```bash
unzip particle-accelerator.zip
cd particle-accelerator
ls -lah
```

Check file types:

```bash
file calibrator sim_kernel.bin
```

Result:

```text
calibrator:     ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
                dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
                for GNU/Linux 3.2.0, stripped

sim_kernel.bin: Khronos SPIR-V binary, little-endian, version 0x010000
```

So we have:

- an x86-64 Linux executable;
- a SPIR-V firmware/kernel image;
- a stripped main binary.

Because symbols are stripped, the first useful sources of information are:

```bash
strings
readelf
objdump
```

and then we can move into a disassembler/debugger such as Ghidra, Binary Ninja, Cutter/radare2, or GDB.

---

# 3. Strings Reconnaissance

Run:

```bash
strings -a calibrator
```

Interesting strings include:

```text
=== Particle Acc Calibrator ===
Initializing coprocessor interface... (simulated)
Loading firmware: sim_kernel.bin
Allocating data buffer (slot 0: input, slot 1: output)...
Submitting calibration run...
Coprocessor hash_out = 0x%08X
Calibrator says: FAIL
Calibrator says: FAIL (hash mismatch)
Calibrator says: PASS
Calibration key: %s
Usage: %s <calibration_sequence>
```

There are two particularly useful observations.

### Observation 1 — input comes from the command line

The usage string tells us the expected interface:

```text
./calibrator <calibration_sequence>
```

### Observation 2 — the coprocessor interface is explicitly described as simulated

The string:

```text
Initializing coprocessor interface... (simulated)
```

suggests that the challenge presents a coprocessor abstraction without necessarily requiring us to emulate an actual accelerator.

We should therefore locate where the binary computes the `hash_out`, performs the final comparison, and prints `PASS`.

---

# 4. ELF Layout

Inspect the section table:

```bash
readelf -S calibrator
```

The relevant sections are:

```text
.text     VA 0x401070  file offset 0x1070
.rodata   VA 0x402000  file offset 0x2000
```

This distinction matters.

For example, an instruction may reference virtual address:

```text
0x4021a0
```

because the process sees `.rodata` around `0x402000`.

The corresponding location **inside the ELF file** is:

```text
0x21a0
```

since `.rodata` itself begins at file offset `0x2000`.

This is important when using tools such as `dd`, `od`, or Python `read_bytes()`.

---

# 5. Program Entry and Main Control Flow

The stripped entry-like function starts at:

```text
0x401070
```

The interesting execution flow is:

```text
argv[1]
   |
   v
strlen()
   |
   v
custom hash
   |
   +---- compare with 0x34F21286
   |
   v
check length == 0x27
   |
   v
generate expected[39]
   |
   v
generate 8-byte key
   |
   v
byte-by-byte validation
   |
   +---- mismatch -> FAIL
   |
   v
regenerate output
   |
   v
print PASS
```

The check order is noteworthy:

1. compute the hash;
2. compare against `0x34F21286`;
3. only then require length `0x27`;
4. if both pass, execute the detailed byte validator.

---

# 6. Custom Hash

The hashing loop begins around:

```text
0x40110d
```

Relevant instructions:

```asm
40110d: mov    eax,0x1
401112: mov    ebx,0x1505

401120: mov    edx,ebx
401122: shl    edx,0x5
401125: add    ebx,edx
401127: movzx  edx,BYTE PTR [r12+rax*1-0x1]
40112d: xor    ebx,edx
```

Translate the loop:

```c
h = 0x1505;

for (i = 0; i < len(input) && i <= 0x3f; i++) {
    h = h + (h << 5);
    h ^= input[i];
}
```

Since:

\[
h + (h \ll 5) = 33h
\]

we get:

\[
H_0 = 0x1505
\]

and

\[
H_{i+1} = (33H_i \bmod 2^{32}) \oplus X_i
\]

The target is hardcoded:

```asm
40114d: cmp    ebx,0x34f21286
```

Therefore:

```text
TARGET_HASH = 0x34F21286
```

This is a DJB2-like custom hash using XOR at the byte-mixing step rather than the classic addition.

---

# 7. Input Length

After hashing:

```asm
401155: cmp    ebp,0x27
401158: je     4011b6
```

Therefore:

```text
0x27 = 39
```

The accepted calibration sequence must be exactly:

```text
39 bytes
```

The eventual recovered flag also turns out to be 39 bytes, which is a useful consistency check.

---

# 8. Function at `0x401360` — Recovering the 8-Byte Key

The function called here:

```asm
4011c0: lea    rdi,[rsp+0x40]
4011c5: call   401360
```

constructs the key used by the validator.

The relevant instructions are:

```asm
401360: xor    eax,eax
401362: mov    ecx,0xffffffd3
401367: mov    edx,0xffffff91
40136c: jmp    40137e

401370: movzx  edx,BYTE PTR [rax+0x4021a8]
401377: movzx  ecx,BYTE PTR [rax+0x4021a0]
40137e: xor    edx,ecx
401380: mov    BYTE PTR [rdi+rax*1],dl
401383: add    rax,0x1
401387: cmp    rax,0x8
40138b: jne    401370
```

The real operation is simply:

```c
for (i = 0; i < 8; i++)
    key[i] = tableA[i] ^ tableB[i];
```

The tables are referenced at virtual addresses:

```text
0x4021a0
0x4021a8
```

Since `.rodata` starts at virtual `0x402000` and file offset `0x2000`, the corresponding file offsets are:

```text
0x21a0
0x21a8
```

Extract:

```bash
od -An -tx1 -j $((0x21a0)) -N 16 calibrator
```

The bytes are:

```text
d3 45 b7 47 54 fe a5 9d
91 56 80 2e ff 33 4a c8
```

Split into two 8-byte tables:

```text
A = d3 45 b7 47 54 fe a5 9d
B = 91 56 80 2e ff 33 4a c8
```

XOR them:

```text
d3 ^ 91 = 42
45 ^ 56 = 13
b7 ^ 80 = 37
47 ^ 2e = 69
54 ^ ff = ab
fe ^ 33 = cd
a5 ^ 4a = ef
9d ^ c8 = 55
```

Thus:

```text
KEY = 42 13 37 69 AB CD EF 55
```

---

# 9. Function at `0x401390` — Generating `expected[39]`

The next helper is called as:

```asm
4011b6: lea    rdi,[rsp+0x70]
4011bb: call   401390
```

Relevant instructions:

```asm
401390: mov    ecx,0xffffffa7
401395: xor    edx,edx
401397: mov    esi,0x50
40139c: jmp    4013a7

4013a0: movzx  esi,BYTE PTR [rdx+0x4021c0]
4013a7: mov    eax,edx
4013a9: imul   eax,edx
4013ac: xor    eax,ecx
4013ae: add    ecx,0x25
4013b1: xor    eax,esi
4013b3: mov    BYTE PTR [rdi+rdx*1],al
4013b6: add    rdx,0x1
4013ba: cmp    rdx,0x27
4013be: jne    4013a0
```

This becomes:

```c
constant = 0xFFFFFFA7;

for (i = 0; i < 39; i++) {
    value = i * i;
    value ^= constant;
    constant += 0x25;
    value ^= source_table[i];
    expected[i] = value & 0xff;
}
```

The source table begins at virtual address:

```text
0x4021c0
```

and therefore its ELF file offset is:

```text
0x21c0
```

The 39 source bytes are:

```text
50 38 2f e5 05 89 8c e6
61 94 86 8a 55 ed 8c 78
8d 8f 93 a6 cc 4a aa 3d
d8 29 6b 7e 72 bc 9c aa
10 e2 6c a8 b0 2b 80
```

The generated expected array is:

```text
f7 f5 da fa 2e f0 2d 7d
ee 31 fb cd a6 cc e5 4b
7a b2 96 a9 d7 43 9b d6
87 1c a6 29 d1 2d e5 49
57 cf 79 d7 7b 72 01
```

---

# 10. The Main Validation Loop

This is the central part of the challenge.

The loop starts at:

```text
0x4011d8
```

Relevant assembly:

```asm
4011d8: mov    rcx,rdx
4011db: rol    al,0x3
4011de: and    ecx,0x7
4011e1: xor    al,BYTE PTR [rsp+rcx*1+0x40]
4011e5: xor    al,BYTE PTR [r12+rdx*1]
4011e9: mov    ecx,eax
4011eb: movzx  eax,BYTE PTR [rsp+rdx*1+0x70]
4011f0: cmp    cl,al
4011f2: jne    40115a
4011f8: add    rdx,0x1
4011fc: cmp    rdx,0x27
401200: jne    4011d8
```

Let's rename the variables:

- \(S_i\): state byte at iteration `i`
- \(K_i\): key byte `key[i & 7]`
- \(X_i\): supplied input byte
- \(E_i\): expected byte

The assembly performs:

```text
ROL8(S_i, 3)
XOR K_i
XOR X_i
```

and checks whether the result equals `expected[i]`.

Therefore:

\[
E_i =
ROL8(S_i,3)
\oplus
K_{i\bmod8}
\oplus
X_i
\]

---

# 11. The Critical State Transition

There is an easy-to-miss instruction:

```asm
4011eb: movzx  eax,BYTE PTR [rsp+rdx*1+0x70]
```

The buffer at `[rsp+0x70]` is the `expected` buffer generated by `0x401390`.

This instruction overwrites `EAX`/`AL` with:

```text
expected[i]
```

So after the comparison, the `AL` state for the next iteration is not the previous input byte.

Instead:

\[
S_{i+1} = E_i
\]

The initial state is set just before the loop:

```asm
4011cc: mov    eax,0xffffffde
```

Thus, at byte zero:

\[
S_0 = 0xDE
\]

and for every later byte:

\[
S_{i+1}=E_i
\]

This observation is the key to solving the challenge.

---

# 12. Algebraic Inversion

The validator equation is:

\[
E_i = ROL8(S_i,3)\oplus K_i\oplus X_i
\]

Because XOR is its own inverse:

\[
X_i =
ROL8(S_i,3)\oplus K_i\oplus E_i
\]

So every input byte can be recovered directly.

There is no need for:

- brute force;
- dictionary attack;
- SMT;
- Z3;
- symbolic execution;
- emulation of the whole program.

The sequence is deterministic.

---

# 13. First Byte by Hand

Initial state:

```text
S0 = DE
```

Rotate left by three bits:

```text
ROL8(DE, 3) = F6
```

First key byte:

```text
K0 = 42
```

First expected byte:

```text
E0 = F7
```

Then:

```text
X0 = F6 ^ 42 ^ F7
```

Calculate:

```text
F6 ^ 42 = B4
B4 ^ F7 = 43
```

`0x43` is:

```text
'C'
```

Therefore the flag begins with:

```text
C
```

Now update the state:

```text
S1 = E0 = F7
```

and repeat for `i = 1 ... 38`.

---

# 14. Recovering All 39 Bytes

The recovered byte sequence is:

```text
43 59 42 45 52 4c 45 41 47 55 45 7b 63 34 6c 31
62 72 34 74 31 30 6e 5f 73 33 71 75 33 6e 63 33
5f 66 30 75 6e 64 7d
```

Convert from hexadecimal to ASCII:

```text
CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
```

The string has exactly:

```text
39 bytes
```

which satisfies the length check.

---

# 15. Reconstructing the Same Operation in Python

A minimal inverse is:

```python
def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff


KEY = bytes.fromhex(
    "42 13 37 69 ab cd ef 55"
)

EXPECTED = bytes.fromhex(
    "f7 f5 da fa 2e f0 2d 7d "
    "ee 31 fb cd a6 cc e5 4b "
    "7a b2 96 a9 d7 43 9b d6 "
    "87 1c a6 29 d1 2d e5 49 "
    "57 cf 79 d7 7b 72 01"
)

state = 0xDE
candidate = bytearray()

for i, expected in enumerate(EXPECTED):
    x = rol8(state, 3) ^ KEY[i & 7] ^ expected
    candidate.append(x)

    # This matches the binary's movzx eax, expected[i].
    state = expected

flag = bytes(candidate)

print(flag.decode())
```

Output:

```text
CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
```

---

# 16. Hash Verification

The challenge has an independent checksum.

Use:

```python
def challenge_hash(data):
    h = 0x1505

    for c in data:
        h = ((h * 33) & 0xffffffff) ^ c

    return h
```

Check the recovered flag:

```python
flag = b"CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}"

print(len(flag))
print(f"{challenge_hash(flag):08x}")
```

Expected:

```text
39
34f21286
```

So:

```text
length      = 39
hash        = 0x34F21286
expected    = 0x34F21286
```

This gives us an independent confirmation of the reverse-engineered input.

---

# 17. Runtime Verification

Run the actual executable:

```bash
./calibrator 'CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}'
```

Observed output:

```text
=== Particle Accelerator Calibrator ===
Initializing coprocessor interface... (simulated)
Loading firmware: sim_kernel.bin
Allocating data buffer (slot 0: input, slot 1: output)...

Submitting calibration run...
Coprocessor hash_out = 0x34F21286
Calibrator says: PASS
Calibration key: CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
```

This is the strongest confirmation because the original challenge binary itself accepts the recovered sequence.

---

# 18. What Is `sim_kernel.bin`?

The second file is a real SPIR-V binary:

```text
sim_kernel.bin: Khronos SPIR-V binary, little-endian
```

Its header begins with the SPIR-V magic:

```text
03 02 23 07
```

and the binary contains the entry point name:

```text
main
```

However, examination of the host executable's dynamic symbols shows only the basic libc functions needed by the simulated application:

```text
puts
strlen
printf
fprintf
```

There are no obvious OpenCL/Vulkan runtime dependencies or GPU execution APIs in the dynamic symbol table.

Combined with the explicit program message:

```text
Initializing coprocessor interface... (simulated)
```

this indicates that the coprocessor behavior is represented by local code rather than requiring a real accelerator runtime.

For solving this challenge, the actual acceptance condition is entirely recoverable from `calibrator`.

The firmware is therefore best treated as a supporting artifact rather than something that must be executed.

---

# 19. Why Brute Force Is Unnecessary

A common first instinct would be to try all possible printable characters for:

```text
CYBERLEAGUE{???????????????????????????}
```

That is unnecessary.

The validation equation is:

\[
E_i =
ROL8(S_i,3)\oplus K_i\oplus X_i
\]

Everything except `X_i` is already known.

Therefore:

\[
\boxed{
X_i =
ROL8(S_i,3)\oplus K_i\oplus E_i
}
\]

This gives exactly one candidate byte at every position.

The time complexity is:

\[
O(39)
\]

which is effectively constant-time for a CTF solve.

---

# 20. Why Z3 Is Also Unnecessary

One could model:

```text
x[0..38]
```

as 8-bit symbolic variables and encode:

```text
ROL8(state, 3) ^ key ^ x[i] == expected[i]
```

in Z3.

But the constraints are linear over XOR plus a permutation (`ROL8`). Since every state byte is known before solving the next byte, symbolic solving adds unnecessary complexity.

The direct inverse is clearer:

```python
x = rol8(state, 3) ^ key[i & 7] ^ expected[i]
```

---

# 21. Optional GDB Verification

For a dynamic reversing session:

```bash
gdb ./calibrator
```

Useful breakpoints:

```gdb
b *0x4011d8
b *0x4011eb
b *0x4011f0
```

Start with:

```gdb
run 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
```

At:

```text
0x4011d8
```

observe that `AL` is rotated:

```asm
rol al, 0x3
```

then XORed against:

```text
[rsp + 0x40 + (i & 7)]
```

and the current input byte.

At:

```text
0x4011eb
```

observe:

```asm
movzx eax, BYTE PTR [rsp+rdx*1+0x70]
```

which replaces `AL` with the current expected byte.

This confirms the state transition described above.

---

# 22. Useful Static Analysis Commands

A reproducible workflow on Linux is:

### File type

```bash
file calibrator sim_kernel.bin
```

### Strings

```bash
strings -a calibrator
```

### Section layout

```bash
readelf -S calibrator
```

### Dynamic imports

```bash
readelf -Ws calibrator | grep ' UND '
```

### Disassembly

```bash
objdump -d -M intel calibrator
```

### Read raw `.rodata`

```bash
od -An -tx1 -j $((0x21a0)) -N 96 calibrator
```

The three relevant tables are located at:

```text
0x21a0 : key table A
0x21a8 : key table B
0x21c0 : expected-source table
```

---

# 23. Full Solver

The following solver extracts the constants directly from the ELF rather than hardcoding the final `KEY` and `EXPECTED` arrays.

```python
#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys

TARGET_HASH = 0x34F21286
INITIAL_HASH = 0x1505
HASH_LIMIT = 0x3F
REQUIRED_LEN = 0x27
INITIAL_STATE = 0xDE


def rol8(x, n):
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def challenge_hash(data):
    h = INITIAL_HASH

    for c in data[:HASH_LIMIT]:
        h = ((h * 33) & 0xFFFFFFFF) ^ c

    return h


def recover_constants(path):
    data = Path(path).read_bytes()

    # .rodata:
    # virtual address = 0x402000
    # file offset     = 0x2000
    #
    # Therefore:
    # VA 0x4021a0 -> file offset 0x21a0
    # VA 0x4021a8 -> file offset 0x21a8
    # VA 0x4021c0 -> file offset 0x21c0

    table_a = data[0x21A0:0x21A8]
    table_b = data[0x21A8:0x21B0]
    source = data[0x21C0:0x21C0 + REQUIRED_LEN]

    if len(table_a) != 8:
        raise RuntimeError("table A extraction failed")

    if len(table_b) != 8:
        raise RuntimeError("table B extraction failed")

    if len(source) != REQUIRED_LEN:
        raise RuntimeError("source table extraction failed")

    key = bytes(a ^ b for a, b in zip(table_a, table_b))

    expected = bytearray()
    constant = 0xFFFFFFA7

    for i, source_byte in enumerate(source):
        value = (i * i) & 0xFFFFFFFF
        value ^= constant
        constant = (constant + 0x25) & 0xFFFFFFFF
        value ^= source_byte
        expected.append(value & 0xFF)

    return key, bytes(expected)


def solve(path):
    key, expected = recover_constants(path)

    state = INITIAL_STATE
    candidate = bytearray()

    for i, expected_byte in enumerate(expected):
        recovered = (
            rol8(state, 3)
            ^ key[i & 7]
            ^ expected_byte
        )

        candidate.append(recovered)

        # Matches:
        # movzx eax, BYTE PTR [rsp+rdx*1+0x70]
        state = expected_byte

    candidate = bytes(candidate)

    if len(candidate) != REQUIRED_LEN:
        raise AssertionError("invalid candidate length")

    actual_hash = challenge_hash(candidate)

    if actual_hash != TARGET_HASH:
        raise AssertionError(
            f"hash mismatch: got 0x{actual_hash:08X}, "
            f"expected 0x{TARGET_HASH:08X}"
        )

    return candidate


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "calibrator")

    flag = solve(binary)

    print(f"[+] flag = {flag.decode()}")
    print(f"[+] len  = {len(flag)}")
    print(f"[+] hash = 0x{challenge_hash(flag):08X}")

    # Optional final verification against the original binary.
    if binary.exists() and (binary.stat().st_mode & 0o111):
        result = subprocess.run(
            [str(binary), flag],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        print("\n--- calibrator output ---")
        print(result.stdout.decode("latin1"), end="")

        if result.stderr:
            print(result.stderr.decode("latin1"), end="")


if __name__ == "__main__":
    main()
```

Save it as:

```text
solve.py
```

then:

```bash
chmod +x solve.py
./solve.py ./calibrator
```

Expected result:

```text
[+] flag = CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
[+] len  = 39
[+] hash = 0x34F21286
```

followed by the original binary's `PASS`.

---

# 24. Solver Logic in Compact Form

The whole challenge can be summarized as:

```text
.rodata
   |
   +-- A[8] ------------------+
   |                          |
   +-- B[8] ------------------+--> KEY = A ^ B
   |
   +-- source[39] ---> expected[39]
                              |
                              v
                     state0 = 0xDE
                              |
                              v
        X[i] = ROL8(state, 3) ^ KEY[i & 7] ^ expected[i]
                              |
                              v
                     state = expected[i]
                              |
                              v
                       recovered flag
                              |
                              v
                       custom hash
                              |
                              v
                         0x34F21286
                              |
                              v
                            PASS
```

---

# 25. Final Flag

```text
CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
```

---

# 26. TL;DR

The binary expects exactly 39 bytes.

It constructs an 8-byte key with:

```text
key[i] = A[i] ^ B[i]
```

It builds a 39-byte expected buffer from a static table using:

```text
value = (i*i) ^ constant ^ source[i]
constant += 0x25
expected[i] = value & 0xff
```

The validator checks:

```text
expected[i] =
    ROL8(state, 3)
    ^ key[i & 7]
    ^ input[i]
```

with:

```text
state0 = 0xDE
state(i+1) = expected[i]
```

Therefore the inverse is:

```text
input[i] =
    ROL8(state, 3)
    ^ key[i & 7]
    ^ expected[i]
```

The recovered sequence is:

```text
CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
```

and its custom hash is:

```text
0x34F21286
```

which makes the original program report:

```text
Calibrator says: PASS
```

---

# 27. Final Takeaway

The challenge looks more complicated because of the accelerator/coprocessor narrative and the additional SPIR-V file. The actual cryptographic/reversing core is deliberately simple once the assembly is translated into a recurrence.

The decisive observations are:

1. **Exact input size:** `0x27 = 39`.
2. **Target hash:** `0x34F21286`.
3. **8-byte key:** recovered by XORing two `.rodata` tables.
4. **Expected bytes:** deterministically generated from a third `.rodata` table.
5. **Validator:** `ROL8 + XOR + XOR`.
6. **State:** overwritten with `expected[i]` every iteration.
7. **Inverse:** directly recover each input byte.
8. **Runtime:** original binary confirms `PASS`.

Therefore no brute force is necessary.

## Flag

```text
CYBERLEAGUE{c4l1br4t10n_s3qu3nc3_f0und}
```
