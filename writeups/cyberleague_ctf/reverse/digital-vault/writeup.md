# Digital Vault — Reverse Engineering Write-Up

## Challenge Information

| Field | Value |
|---|---|
| **Category** | Reverse Engineering |
| **Challenge** | Digital Vault |
| **Server** | `http://cyberleague-shared-alb-586365318.ap-southeast-1.elb.amazonaws.com:30104` |
| **Flag format** | `CYBERLEAGUE{...}` |
| **Recovered flag** | `CYBERLEAGUE{v4ult_4cc3ss_gr4nt3d}` |

---

## 1. Challenge Description

> Forensics pulled this vault login portal off a suspect's seized laptop. It still runs, and it still wants an access code that was never recovered from the original device. Everything the portal needs to judge an attempt travels with the page itself — there is nothing left on the other end to ask. Open it in a browser, work out what it is actually checking, and recover the code that unlocks the vault.

The key clue is:

> **Everything the portal needs to judge an attempt travels with the page itself.**

This strongly indicates a **client-side validator**. Instead of attacking the HTTP endpoint, the correct approach is to inspect all resources delivered with the page and reconstruct the local validation algorithm.

---

## 2. Files in the Challenge

The supplied archive contains three files:

```text
digital-vault.zip
├── index.html
├── worker.js
└── checker.wasm
```

Each layer contributes part of the validator:

| File | Function |
|---|---|
| `index.html` | User interface, hard-coded configuration, input masking |
| `worker.js` | Loads WASM, derives a state key, stores it in IndexedDB, dispatches checks |
| `checker.wasm` | Implements the PRNG and final byte-by-byte comparison |

The important data flow is:

```text
index.html
    │
    │ cfg = 0xCAFEBABE
    ▼
worker.js
    │
    ├── seed = cfg XOR 0xFDB97531
    ├── _sk  = seed XOR 0xDEADBEEF
    │
    ▼
checker.wasm
    │
    ├── initialize global PRNG state
    ├── generate one PRNG byte per character
    ├── load embedded comparison table
    ├── derive repeating key byte from _sk
    └── compare against the submitted payload
```

---

## 3. `index.html`: Find the First Constant

The page contains:

```javascript
var _cfg = [0xCA, 0xFE, 0xBA, 0xBE];
var _c = (_cfg[0] << 24 | _cfg[1] << 16 | _cfg[2] << 8 | _cfg[3]) >>> 0;
```

Therefore:

```text
cfg = 0xCAFEBABE
```

When checking the input, JavaScript performs another transformation:

```javascript
var bytes = enc.encode(raw);
var masked = new Uint8Array(bytes.length);
for (var j = 0; j < bytes.length; j++) {
    masked[j] = bytes[j] ^ 0x42;
}
```

So the browser actually sends:

```text
payload[i] = raw[i] XOR 0x42
```

At first glance this resembles encryption, but XOR with a fixed constant is completely reversible. More importantly, the WASM validator performs another XOR with `0x42`, which will cancel this transformation. Therefore there is no need to recover any cryptographic key for this layer.

---

## 4. `worker.js`: Recover the Deterministic State

The initialization handler contains:

```javascript
var cfg = msg.cfg >>> 0;
var seed = (cfg ^ 0xFDB97531) >>> 0;
wasmInstance.exports.f0(seed);

_sk = (seed ^ 0xDEADBEEF) >>> 0;
return storeSK(_sk);
```

### 4.1 Recover `seed`

```text
cfg  = 0xCAFEBABE
     XOR 0xFDB97531
     = 0x3747CF8F
```

Thus the initial state is:

```text
S0 = 0x3747CF8F
```

### 4.2 Recover `_sk`

```text
_sk = seed XOR 0xDEADBEEF
    = 0x3747CF8F XOR 0xDEADBEEF
    = 0xE9EA7160
```

This immediately tells us that IndexedDB is **not hiding an unknown secret**. The value stored under the `sk` key is deterministically generated from a hard-coded public value in the page.

The following check in `worker.js`:

```javascript
loadSK().then(function (stored) {
    if (stored !== _sk) {
        self.postMessage({ type: 'result', success: false, reason: 'bad_state' });
        return;
    }
    ...
});
```

is therefore only a consistency check.

---

## 5. `checker.wasm`: Understand the Exports

The WASM module exports:

```text
memory
f0
f1
```

Their roles are:

```text
f0(seed)        -> initialize the mutable global PRNG state
f1(ptr,len,sk)  -> validate the submitted 33-byte candidate
```

### 5.1 `f0()`

The first function is effectively:

```text
global[0] = argument_0
```

Since the worker calls:

```javascript
wasmInstance.exports.f0(seed);
```

we know:

```text
global[0] = 0x3747CF8F
```

---

## 6. Reverse the PRNG Helper

The second WASM function contains the following instruction pattern:

```text
global.get 0
i32.const 0x19660D
i32.mul
i32.const 0x3C6EF35F
i32.add
global.set 0
global.get 0
```

This is the standard shape of a 32-bit Linear Congruential Generator (LCG):

$$
S_{i+1} = (S_i \times 0x19660D + 0x3C6EF35F) \bmod 2^{32}
$$

In Python, one iteration is simply:

```python
state = (state * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
```

The validator then uses only the least significant byte:

```python
prng_byte = state & 0xFF
```

So the effective stream is deterministic once `S0` is known.

---

## 7. Recover the Embedded Expected Table

The WASM data section places 33 bytes at memory offset `0x100`.

The raw table is:

```text
81 b1 8c 9f c4 e0 37 bf ad 45 e3 a9
48 60 df 1a 66 07 aa c9 c5 2f 71 bd
65 e7 04 96 20 b0 49 22 5f
```

Let this be:

```text
T[0 .. 32]
```

The validation loop loads a byte from `0x100 + i`, so each iteration uses exactly one byte of this table.

---

## 8. Reverse `f1()`

### 8.1 Length check

The function starts with an explicit check equivalent to:

```text
if len != 33:
    return 0
```

Therefore the candidate must be exactly **33 bytes** long.

### 8.2 Reinitialize the state from `stored`

Before the loop, `f1()` performs:

```text
stored XOR 0xDEADBEEF
```

Since:

```text
stored = seed XOR 0xDEADBEEF
```

we get:

```text
stored XOR 0xDEADBEEF
= seed
= 0x3747CF8F
```

So the validation state is deterministic and starts from the same value recovered from the worker.

### 8.3 Extract the repeating key byte

The WASM shifts `stored` by:

```text
(i & 3) * 8
```

and then keeps the low byte. Therefore the key cycles through the four bytes of `0xE9EA7160` in little-endian order:

```text
stored = 0xE9EA7160

K[0] = 0x60
K[1] = 0x71
K[2] = 0xEA
K[3] = 0xE9
K[4] = 0x60
K[5] = 0x71
...
```

So:

```text
K[i] = (stored >> (8 * (i mod 4))) & 0xFF
```

### 8.4 The actual byte relation

The important portion of the WASM loop can be represented as:

```text
state       = LCG(state)
prng_byte   = state & 0xFF
key_byte    = (stored >> ((i & 3) * 8)) & 0xFF
left_side   = T[i] XOR prng_byte XOR key_byte
right_side  = payload[i] XOR 0x42
```

and then:

```text
left_side == right_side
```

The browser sent:

```text
payload[i] = raw[i] XOR 0x42
```

Therefore:

```text
right_side
= (raw[i] XOR 0x42) XOR 0x42
= raw[i]
```

So the complete equation collapses to:

$$
raw_i = T_i \oplus P_i \oplus K_i
$$

where:

```text
P[i] = S[i] & 0xFF
```

This is the crucial reversing step.

---

## 9. Final Inverse Formula

The complete algorithm is:

```text
S0 = 0x3747CF8F

for i = 0 .. 32:

    S(i+1) = (S(i) * 0x19660D + 0x3C6EF35F) mod 2^32

    P(i) = S(i+1) & 0xFF

    K(i) = (0xE9EA7160 >> (8 * (i mod 4))) & 0xFF

    raw(i) = T(i) XOR P(i) XOR K(i)
```

No brute force is needed. No Z3 model is needed. The entire input is directly recoverable in `O(33)` operations.

---

## 10. Byte-by-Byte Recovery

| i | `T[i]` | LCG state | `P[i]` | `K[i]` | recovered | ASCII |
|---:|---:|---:|---:|---:|---:|:---:|
| 0 | `81` | `0xecbe77a2` | `a2` | `60` | `43` | `C` |
| 1 | `b1` | `0xd4979299` | `99` | `71` | `59` | `Y` |
| 2 | `8c` | `0xbd7b5b24` | `24` | `ea` | `42` | `B` |
| 3 | `9f` | `0xe886ec33` | `33` | `e9` | `45` | `E` |
| 4 | `c4` | `0xde6043f6` | `f6` | `60` | `52` | `R` |
| 5 | `e0` | `0x856c6add` | `dd` | `71` | `4c` | `L` |
| 6 | `37` | `0xa5196e98` | `98` | `ea` | `45` | `E` |
| 7 | `bf` | `0x8da22117` | `17` | `e9` | `41` | `A` |
| 8 | `ad` | `0x4218cb8a` | `8a` | `60` | `47` | `G` |
| 9 | `45` | `0x59444561` | `61` | `71` | `55` | `U` |
| 10 | `e3` | `0xbf041f4c` | `4c` | `ea` | `45` | `E` |
| 11 | `a9` | `0xa288d23b` | `3b` | `e9` | `7b` | `{` |
| 12 | `48` | `0x88e8225e` | `5e` | `60` | `76` | `v` |
| 13 | `60` | `0x09182625` | `25` | `71` | `34` | `4` |
| 14 | `df` | `0x0b78a140` | `40` | `ea` | `75` | `u` |
| 15 | `1a` | `0xa10ea39f` | `9f` | `e9` | `6c` | `l` |
| 16 | `66` | `0x39e59c72` | `72` | `60` | `74` | `t` |
| 17 | `07` | `0xf08f5129` | `29` | `71` | `5f` | `_` |
| 18 | `aa` | `0x7b0d6874` | `74` | `ea` | `34` | `4` |
| 19 | `c9` | `0x070f7943` | `43` | `e9` | `63` | `c` |
| 20 | `c5` | `0x9a13cdc6` | `c6` | `60` | `63` | `c` |
| 21 | `2f` | `0x0bc34a6d` | `6d` | `71` | `33` | `3` |
| 22 | `71` | `0xe9a628e8` | `e8` | `ea` | `73` | `s` |
| 23 | `bd` | `0x4cd37727` | `27` | `e9` | `73` | `s` |
| 24 | `65` | `0x07748a5a` | `5a` | `60` | `5f` | `_` |
| 25 | `e7` | `0x8f43d5f1` | `f1` | `71` | `67` | `g` |
| 26 | `04` | `0x6ea7d69c` | `9c` | `ea` | `72` | `r` |
| 27 | `96` | `0xafb3014b` | `4b` | `e9` | `34` | `4` |
| 28 | `20` | `0x9b5ce62e` | `2e` | `60` | `6e` | `n` |
| 29 | `b0` | `0x9e5af7b5` | `b5` | `71` | `74` | `t` |
| 30 | `49` | `0xb66ca590` | `90` | `ea` | `33` | `3` |
| 31 | `22` | `0xf4fabbaf` | `af` | `e9` | `64` | `d` |
| 32 | `5f` | `0xe8093542` | `42` | `60` | `7d` | `}` |

The recovered bytes are:

```text
43 59 42 45 52 4c 45 41 47 55 45 7b
76 34 75 6c 74 5f 34 63 63 33 73 73
5f 67 72 34 6e 74 33 64 7d
```

ASCII-decoding them gives:

```text
CYBERLEAGUE{v4ult_4cc3ss_gr4nt3d}
```

---

## 11. Solver

The following Python 3 solver parses the challenge archive directly. It does not hard-code the 33-byte table; it extracts the table from the WASM data section and extracts the constants from the HTML, JavaScript, and WASM code.

### `solve_digital_vault.py`

```python
#!/usr/bin/env python3
"""Solver for the CyberLeague 'Digital Vault' challenge.

Usage:
    python3 solve_digital_vault.py digital-vault.zip
    python3 solve_digital_vault.py /path/to/digital-vault-directory
"""
from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

MASK32 = 0xFFFFFFFF


def uleb(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated ULEB128")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 35:
            raise ValueError("invalid ULEB128")


def read_files(src: Path) -> dict[str, bytes]:
    if src.is_dir():
        return {name: (src / name).read_bytes() for name in ("index.html", "worker.js", "checker.wasm")}
    with zipfile.ZipFile(src) as zf:
        needed = {"index.html", "worker.js", "checker.wasm"}
        names = set(zf.namelist())
        # Support a single top-level directory inside the zip.
        mapping: dict[str, str] = {}
        for wanted in needed:
            matches = [n for n in names if n == wanted or n.endswith("/" + wanted)]
            if len(matches) != 1:
                raise FileNotFoundError(f"could not uniquely locate {wanted} in archive")
            mapping[wanted] = matches[0]
        return {k: zf.read(v) for k, v in mapping.items()}


def extract_cfg(index_html: bytes) -> int:
    text = index_html.decode("utf-8")
    m = re.search(r"_cfg\s*=\s*\[\s*([^\]]+)\]", text)
    if not m:
        raise ValueError("could not find _cfg in index.html")
    vals = [int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))]
    if len(vals) != 4:
        raise ValueError(f"unexpected _cfg array: {vals!r}")
    cfg = ((vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]) & MASK32
    return cfg


def extract_worker_constants(worker_js: bytes) -> tuple[int, int]:
    text = worker_js.decode("utf-8")
    seed_m = re.search(r"cfg\s*\^\s*(0x[0-9a-fA-F]+)", text)
    sk_m = re.search(r"seed\s*\^\s*(0x[0-9a-fA-F]+)", text)
    if not seed_m or not sk_m:
        raise ValueError("could not recover worker.js XOR constants")
    return int(seed_m.group(1), 0) & MASK32, int(sk_m.group(1), 0) & MASK32


def parse_code_bodies(wasm: bytes) -> list[bytes]:
    pos = 8
    while pos < len(wasm):
        section_id = wasm[pos]
        pos += 1
        size, pos = uleb(wasm, pos)
        end = pos + size
        if section_id == 10:  # code section
            count, p = uleb(wasm, pos)
            bodies = []
            for _ in range(count):
                body_size, p = uleb(wasm, p)
                bodies.append(wasm[p:p + body_size])
                p += body_size
            return bodies
        pos = end
    raise ValueError("no code section found")


def parse_data_segments(wasm: bytes) -> list[tuple[int, bytes]]:
    pos = 8
    result: list[tuple[int, bytes]] = []
    while pos < len(wasm):
        section_id = wasm[pos]
        pos += 1
        size, pos = uleb(wasm, pos)
        end = pos + size
        if section_id == 11:  # data section
            count, p = uleb(wasm, pos)
            for _ in range(count):
                flags, p = uleb(wasm, p)
                if flags == 0:
                    # active segment, implicit memory 0: offset expr = i32.const <uleb>, end
                    if wasm[p] != 0x41:
                        raise ValueError("unexpected data-segment offset expression")
                    offset, p = uleb(wasm, p + 1)
                    if wasm[p] != 0x0B:
                        raise ValueError("malformed data-segment offset expression")
                    p += 1
                elif flags == 2:
                    # active segment with explicit memory index
                    _, p = uleb(wasm, p)
                    if wasm[p] != 0x41:
                        raise ValueError("unexpected explicit-memory offset expression")
                    offset, p = uleb(wasm, p + 1)
                    if wasm[p] != 0x0B:
                        raise ValueError("malformed data-segment offset expression")
                    p += 1
                else:
                    # Passive or unsupported form; this challenge uses only active data.
                    raise ValueError(f"unsupported data-segment flags {flags}")
                length, p = uleb(wasm, p)
                data = wasm[p:p + length]
                p += length
                result.append((offset, data))
        pos = end
    return result


def extract_lcg_constants(wasm: bytes) -> tuple[int, int]:
    bodies = parse_code_bodies(wasm)
    if len(bodies) < 2:
        raise ValueError("unexpected function count")
    # Hidden helper is function index 1:
    # global.get 0; i32.const M; i32.mul; i32.const C; i32.add; global.set 0; global.get 0
    body = bodies[1]
    mul_at = body.find(bytes([0x41]))
    if mul_at < 0:
        raise ValueError("LCG multiply constant not found")
    # First i32.const is M and is immediately followed by i32.mul (0x6c).
    pos = mul_at
    # Skip local-decl prefix, find an i32.const followed by mul.
    while True:
        pos = body.find(bytes([0x41]), pos)
        if pos < 0:
            break
        value, after = uleb(body, pos + 1)
        if after < len(body) and body[after] == 0x6C:
            M = value & MASK32
            cpos = after + 1
            if body[cpos] != 0x41:
                raise ValueError("LCG add constant not found")
            C, after_c = uleb(body, cpos + 1)
            if after_c >= len(body) or body[after_c] != 0x6A:
                raise ValueError("malformed LCG helper")
            return M, C & MASK32
        pos += 1
    raise ValueError("LCG constants not found")


def solve(src: Path) -> str:
    files = read_files(src)
    cfg = extract_cfg(files["index.html"])
    seed_xor, sk_xor = extract_worker_constants(files["worker.js"])
    seed = (cfg ^ seed_xor) & MASK32
    stored = (seed ^ sk_xor) & MASK32

    M, C = extract_lcg_constants(files["checker.wasm"])
    segments = parse_data_segments(files["checker.wasm"])
    table = next((data for offset, data in segments if offset == 0x100 and len(data) == 33), None)
    if table is None:
        raise ValueError("33-byte validator table at 0x100 not found")

    # f1 starts the helper state with stored ^ DEADBEEF, which is exactly seed.
    state = (stored ^ sk_xor) & MASK32
    out = bytearray()
    for i, expected in enumerate(table):
        state = (state * M + C) & MASK32
        prng_byte = state & 0xFF
        sk_byte = (stored >> ((i & 3) * 8)) & 0xFF
        # WASM computes:
        #   local8 = table[i] ^ (state & 0xff) ^ selected_SK_byte
        #   local9 = payload[i] ^ 0x42
        # and requires local8 == local9. Browser JS already sent payload=raw^0x42,
        # so the two XORs cancel and raw == local8.
        out.append(expected ^ prng_byte ^ sk_byte)

    return out.decode("ascii")


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("digital-vault.zip")
    flag = solve(src)
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()

```

Example execution:

```text
$ python3 solve_digital_vault.py digital-vault.zip
[+] FLAG: CYBERLEAGUE{v4ult_4cc3ss_gr4nt3d}
```

The same solver can also operate on an extracted challenge directory containing:

```text
index.html
worker.js
checker.wasm
```

---

## 12. Verification Against the Original Validator

The recovered candidate has:

```text
length = 33
```

and the WASM validator returns success:

```text
f1(0, 33, stored) = 1
```

Therefore the result is not merely a plausible plaintext. It satisfies the original validation equation.

The browser-side masking also behaves as expected:

```text
raw
 -> XOR 0x42
 -> payload
 -> WASM XOR 0x42
 -> raw
```

which proves why the final recovered string can be entered directly into the portal.

---

## 13. Why the Challenge Is Solvable Offline

The challenge can be solved entirely from the supplied files because all validation inputs are local and deterministic:

| Component | Source | Recoverable? |
|---|---|:---:|
| Configuration | `index.html` | Yes |
| Seed derivation | `worker.js` | Yes |
| Stored key | `worker.js` | Yes |
| PRNG multiplier | `checker.wasm` | Yes |
| PRNG increment | `checker.wasm` | Yes |
| Comparison table | `checker.wasm` data section | Yes |
| Input mask | `index.html` / `checker.wasm` | Yes |
| Required length | `checker.wasm` | Yes |
| Remote secret | None | Not needed |

The use of IndexedDB does not change this conclusion. It only stores a deterministic value generated from the page configuration.

---

## 14. Reversing Strategy Summary

The complete reversing chain is:

```text
1. Inspect index.html
       │
       └── cfg = 0xCAFEBABE

2. Inspect worker.js
       │
       ├── seed = cfg XOR 0xFDB97531
       │          = 0x3747CF8F
       │
       └── _sk = seed XOR 0xDEADBEEF
                  = 0xE9EA7160

3. Inspect checker.wasm
       │
       ├── f0() stores the seed
       ├── f1() requires length = 33
       ├── LCG:
       │      S = S * 0x19660D + 0x3C6EF35F mod 2^32
       │
       └── table at memory 0x100

4. Recover key stream
       │
       └── 60 71 EA E9 repeating

5. Invert XOR relation
       │
       └── raw[i] = T[i] XOR PRNG[i] XOR K[i]

6. Decode 33 bytes
       │
       └── CYBERLEAGUE{v4ult_4cc3ss_gr4nt3d}
```

---

## 15. Key Lessons

### 15.1 Read the client before attacking the server

The challenge description explicitly says that everything required to judge the input is shipped with the page. That is a direct hint to perform local static analysis first.

### 15.2 Follow the data flow across languages

The validator is split across HTML, JavaScript, a Web Worker, IndexedDB, and WebAssembly. Looking at only one layer would make the logic appear more complicated than it actually is.

### 15.3 XOR layers often collapse

A fixed XOR is self-inverse:

$$
(X \oplus C) \oplus C = X
$$

This means apparently separate masking operations can cancel completely when the full data flow is reconstructed.

### 15.4 Deterministic state is not a secret

A value that is generated from hard-coded public constants and then placed into IndexedDB is not cryptographically secret. Reversing the derivation is enough to reproduce it.

### 15.5 WASM still has to expose its algorithm

WebAssembly can make casual inspection less convenient, but its instructions, constants, memory segments, globals, imports, and exports remain recoverable. It should be analyzed as a normal executable format rather than treated as a black box.

---

## 16. Final Flag

```text
CYBERLEAGUE{v4ult_4cc3ss_gr4nt3d}
```

---

## Appendix A — Minimal Manual Solver

Once the constants are known, the core solver is only a few lines:

```python
seed = 0x3747CF8F
stored = 0xE9EA7160
M = 0x19660D
C = 0x3C6EF35F

table = bytes.fromhex(
    "81 b1 8c 9f c4 e0 37 bf ad 45 e3 a9 "
    "48 60 df 1a 66 07 aa c9 c5 2f 71 bd "
    "65 e7 04 96 20 b0 49 22 5f"
)

state = seed
out = bytearray()

for i, t in enumerate(table):
    state = (state * M + C) & 0xffffffff
    p = state & 0xff
    k = (stored >> (8 * (i & 3))) & 0xff
    out.append(t ^ p ^ k)

print(out.decode())
```

Output:

```text
CYBERLEAGUE{v4ult_4cc3ss_gr4nt3d}
```
