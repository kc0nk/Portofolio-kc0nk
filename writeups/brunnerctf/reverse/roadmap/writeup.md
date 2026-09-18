# Roadmap

- **Category:** Reverse Engineering
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Reverse-engineering konfigurasi Nginx map yang menyamarkan DFA/state machine. Route harus 41 karakter dan seluruh transisi harus berakhir pada `CLEARED`.

## Metode
Modelkan setiap map sebagai state transition, lalu balik badge hex menjadi karakter.

## Command / primitive
```http
GET /<41-character-string> HTTP/1.1
map $uri $route
map $route $route_len_ok
map "${cp_state}:${badge}" $next_state
```

## Rumus / constraint
```text
route_len == 41
cp_final == CLEARED
access = 1 iff reached_cleared == 1 AND route_len_ok == 1
```

## Solver / code snippet
```python
payload = b"brunner{c0rp0r4t3_r04dm4p_t0_ng1nx_h34rt}"
assert len(payload) == 41
request = (
    b"GET /" + payload + b" HTTP/1.1\r\n"
    + b"Host: " + HOST.encode() + b"\r\n"
    + b"Connection: close\r\n\r\n"
)
```

## Hasil
```text
brunner{c0rp0r4t3_r04dm4p_t0_ng1nx_h34rt}
```
