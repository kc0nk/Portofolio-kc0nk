# pickle

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** Easy · **Flag:** `pwnsec{d51962f679918668}`

**Tujuan:** membaca `/app/flag.txt` lewat deserialisasi pickle Python yang "dibatasi" (`RestrictedUnpickler`).

**Inti kerentanan:** fungsi `check()` menaruh `pickletools.dis()` **dan** pengecekan tekstual opcode `REDUCE` di satu blok `try` yang menekan semua exception. Karena byte `STOP` (byte `.`) diblokir oleh blocklist, stream pickle bisa dibuat **tanpa opcode `STOP`**. Ini membuat `pickletools.dis()` gagal dengan `ValueError` di EOF — sehingga cek `REDUCE` **dilewati sepenuhnya**. Namun unpickler asli tetap mengeksekusi semua opcode (termasuk efek samping seperti pemanggilan fungsi) sebelum mencapai EOF, dan `restore()` menekan exception terakhirnya.

**Alur eksploitasi:**
- Modul yang diizinkan: hanya yang berawalan `sessionstore` atau `collections`.
- Trik: resolusi nama bertitik (`STACK_GLOBAL`) di bawah objek `sessionstore.render` yang diizinkan bisa mengekspos `render.__globals__.__class__.__getitem__` (descriptor `dict.__getitem__` yang tidak terikat). Dengan ini bisa diambil `render.__globals__['__builtins__']` → dapat `open`, `getattr`, `print`.
- Payload memanggil `open('/app/flag.txt').read()` lalu `print(...)`, yang outputnya sudah dialihkan Flask ke response — tanpa satupun string terlarang (`.`, `flag`, `getattr`) muncul di raw pickle (dienkode `\uXXXX`).

**Pelajaran:** validator tidak boleh tetap lanjut ke deserializer berbahaya setelah parser gagal; allowlist nama modul tidak cukup jika resolusi nama bertitik bisa mengekspos seluruh object graph dari modul yang diizinkan.

---
