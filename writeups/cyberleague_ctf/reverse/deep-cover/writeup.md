# 2. Deep Cover

**Kategori:** Reverse Engineering  
**Target:** `nc 52.220.1.140 4444`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

Challenge menyediakan executable `asset` dan artifact kernel-side berupa object eBPF `monitor.ko.o`. Program utama tampak hanya menampilkan cover story, tetapi ternyata mencari kondisi/path tertentu sebelum mau membaca `/flag`.

## 2.1 Anti-debugging

Entry point program utama berada di sekitar:

```text
0x4010d0
```

Program membuka:

```text
/proc/self/status
```

kemudian mencari:

```text
TracerPid:
```

Alurnya:

```text
TracerPid == 0  → lanjut
TracerPid != 0  → output disuppress
```

Konsekuensinya, pada saat reversing runtime, `gdb`, `strace`, atau `ltrace` dapat mengubah perilaku program.

## 2.2 Hidden Trigger pada `asset`

Fungsi sekitar `0x4013b0` memanggil `getcwd()` lalu melakukan pencarian terhadap string tersembunyi.

Data di sekitar:

```text
0x402150
```

berisi:

```text
b399a7cf bdf2b0ca aac59f8a acc4a700
```

Kunci XOR yang digunakan adalah:

```text
de ad c0 fe
```

atau konstanta:

```text
DEADC0FE
```

Setelah decoding ditemukan marker pemicu yang sesuai dengan artifact eBPF:

```text
m4g1c_p4th_trig\xfe
```

`asset` kemudian melakukan pencarian berbasis `strstr()` terhadap CWD.

## 2.3 Artifact eBPF

Pada `monitor.ko.o` terdapat data konfigurasi `cfg_data` dan `cfg_mask`.

`cfg_data` terdiri dari empat word 32-bit yang kemudian di-XOR dengan mask:

```text
0xFEC0ADDE
```

Hasil decode menghasilkan marker:

```text
m4g1c_p4th_trig\xfe
```

Hal yang menarik adalah terdapat ketidaksesuaian representasi antara byte yang dipakai binary dan string yang secara intuitif akan dicari.

## 2.4 Exploit Path

Target bukanlah memory corruption. Kita hanya perlu membuat process memiliki CWD yang memenuhi predicate internal.

Payload path menggunakan byte `0xfe`, sehingga pendekatan aman adalah menggunakan pathname sebagai bytes.

Contoh shell command:

```bash
mkdir -- "$(printf 'm4g1c_p4th_trig\376')"
cd -- "$(printf 'm4g1c_p4th_trig\376')"
/path/ke/asset
```

## 2.5 Solver

```python
#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path

MONITOR = Path("monitor.ko.o")
ASSET = Path("asset")


def extract_marker(monitor_path: Path) -> bytes:
    data = monitor_path.read_bytes()

    cipher = bytes.fromhex(
        "b399a7cf"
        "bdf2b0ca"
        "aac59f8a"
        "acc4a700"
    )
    mask = bytes.fromhex("deadc0fe")

    pos = data.find(cipher)
    if pos == -1:
        raise RuntimeError("cfg_data tidak ditemukan")

    cfg = data[pos:pos + 16]
    out = bytearray()

    for i in range(0, 16, 4):
        for j in range(4):
            out.append(cfg[i + j] ^ mask[j])

    return bytes(out)


def run_asset(asset_path: Path, marker: bytes) -> int:
    asset_path = asset_path.resolve()

    root = b"/tmp"
    dirname = b"deep-cover-trigger-" + marker
    trigger_dir = os.path.join(root, dirname)

    os.makedirs(trigger_dir, exist_ok=True)

    print(f"[+] marker = {marker!r}")
    print(f"[+] marker hex = {marker.hex()}")
    print(f"[+] trigger directory = {trigger_dir!r}")

    proc = subprocess.run(
        [os.fsencode(str(asset_path))],
        cwd=trigger_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    sys.stdout.write(proc.stdout.decode("utf-8", errors="replace"))
    if proc.stderr:
        sys.stderr.write(
            proc.stderr.decode("utf-8", errors="replace")
        )

    return proc.returncode


def main() -> None:
    marker = extract_marker(
        Path(sys.argv[1]) if len(sys.argv) > 1 else MONITOR
    )
    asset = Path(sys.argv[2]) if len(sys.argv) > 2 else ASSET

    expected = b"m4g1c_p4th_trig\xfe"
    if marker != expected:
        print(f"[!] Marker unexpected: {marker!r}")

    run_asset(asset, marker)


if __name__ == "__main__":
    main()
```

## 2.6 Output Verifikasi

```text
[+] marker = b'm4g1c_p4th_trig\xfe'
[+] marker hex = 6d346731635f703474685f726967fe
[+] menjalankan asset...
Deep Cover
==========
Checking environment...

Cover broken. Signal received.
CYBERLEAGUE{c0v3r_bl0wn_s1gn4l_f0und}
```

## Flag

```text
CYBERLEAGUE{c0v3r_bl0wn_s1gn4l_f0und}
```

---
