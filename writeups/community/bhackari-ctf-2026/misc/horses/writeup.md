---
ctf: "BhAcKAri CTF 2026"
kategori: "Misc"
challenge: "Horses"
flag: "bhackariCTF{C0rr1C4vall0o0!1!1!1}"
teknik: "Sandbox d8 ter-patch masih mengekspos eval secara global; bug credits tak-tervalidasi + shop item 'Terminal' membuka shell eval untuk membaca const global"
sumber: "https://github.com/Abdelkad3r/bhackari-ctf-2026"
---

# Horses — BhAcKAri CTF 2026 (Misc)

## Deskripsi Singkat

Challenge ini berbagi remote dan bundle attachment dengan challenge pwn *Engine-Powered Horses*, tapi varian misc-nya hanya mencakup `ascii-horses.js`. `FLAG_1` adalah `const` di scope top-level script d8. Tugasnya: membocorkannya dari sandbox d8 ter-patch yang sudah kehilangan sebagian besar primitive file/network/Worker.

## Analisis

**Yang bertahan di d8 ter-patch.** Patch-nya menghapus `read`, `readbuffer`, `load`, `writeFile`, `setTimeout`, `Realm`, `Worker`, `os`, `d8`, `performance`, dan `printErr`. Yang masih ada di global object: `print`, `readline`, `quit`, dan **ECMAScript standar** — termasuk `eval`.

**Bug 1 — Load Game menerima credits sembarang** (`ascii-horses.js:235`): save blob `{"c": 999999999, "s": []}` lolos `JSON.parse` dan langsung ditugaskan ke global `credits`. Tanpa HMAC, tanpa batas sanity.

**Bug 2 — item Shop "Terminal" adalah loop `eval` penuh** (`ascii-horses.js:387`): item `🐴 Terminal 🐴` berharga 133.700 credits, membuka `while(true) { eval(readline()) }`.

## Eksploitasi / Solusi

1. Menu opsi **5** (Load Game) → paste `{"c": 999999999, "s": []}` → credits jadi 999.999.999.
2. Menu opsi **3** (Shop) → item **3** (🐴 Terminal 🐴) → biayanya 133.700 credits → masuk shell loop.
3. Ketik `FLAG_1`. `eval("FLAG_1")` me-resolve `const` global dan `print` mencetaknya.

Flag: *"Corri Cavallo!"* — Italia untuk "Lari, kuda!"

## Catatan / Insight

**Pelajaran untuk defender:** **`eval` di kode user-facing adalah primitive sandbox-escape bahkan ketika sandbox di sekitarnya sudah dipatch habis.** Menghapus `read`/`Worker`/`os` dari patch d8 tidak relevan kalau kode aplikasi yang jalan *di dalam* d8 memanggil `eval(readline())`. Bug-nya bukan di V8 — ada di JS yang dikirimkan pembuat challenge. Pelajaran produksi: fitur "developer terminal" / "admin console" apa pun yang backend-nya `eval` akan ditemukan dan dipakai.

## Flag

```
bhackariCTF{C0rr1C4vall0o0!1!1!1}
```
