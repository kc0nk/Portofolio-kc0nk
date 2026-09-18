# mouse in the house

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** tidak dicantumkan · **Flag:** `pwnsec{c723fccfe77783ae}`

**Tujuan:** membaca note privat milik sesi bot.

**Inti kerentanan (dua bagian):**
1. **Gadget dynamic-import PrismJS lolos DOMPurify** — `src/global.js` PrismJS membaca atribut `data-prism-plugins` dan `data-prism-plugin-path` lalu memanggil `import(...)`. Atribut ini tidak dibersihkan DOMPurify. Payload 80 karakter:
   ```html
   <p data-prism-plugins data-prism-plugin-path=data:text/javascript,import(name)#>
   ```
   Ini memicu `import(name)` di mana `window.name` diisi modul JS kedua (`data:text/javascript,...`) → RCE JavaScript tanpa butuh `unsafe-eval`.
2. **`window.opener = null` tidak mencegah kebocoran referensi via `postMessage`** — meski note memutus `opener`, ketika parent asli mengirim `postMessage` ke popup, popup tetap menerima `event.source` yang merupakan `WindowProxy` parent. Setelah parent bernavigasi ke halaman internal `/notes/`, parent dan popup jadi same-origin, sehingga popup bisa membaca DOM parent (daftar ID note) dan `fetch()` tiap `/notes/:id` (diizinkan `connect-src`) sampai ketemu note yang mengandung flag.

**Pelajaran:** sanitizer DOM bisa lolos jika library lain membaca atribut DOM sebagai konfigurasi dynamic-import; `window.opener = null` tidak mencabut referensi window yang sudah didapat lewat `postMessage`/`event.source`.

---
