# readonce

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** Hard · **Flag:** `pwnsec{f73af0e53bf677dc}`

**Tujuan:** membaca isi `/api/flag` yang hanya bisa diakses sesi bot admin.

**Inti kerentanan:**
- `GET /review?rid=RID&u=URL` menyimpan URL attacker (**tanpa autentikasi**) sebagai `<script nonce="SERVER_NONCE" src="ATTACKER_URL">` di `/sandbox`. Karena elemen script ini dibuat oleh parser dengan nonce server yang benar, CSP `script-src 'nonce-...'` + Trusted Types tetap **mengizinkan** script attacker jalan.
- `/review` normal menaruh `/sandbox` dalam iframe terbatas — tapi bot bisa diarahkan (via redirect 302) langsung ke `/sandbox` sebagai dokumen **top-level**, sehingga script attacker berjalan di origin admin tanpa sandbox iframe.

**Alur eksploitasi:**
1. Redirect URL yang dikunjungi bot ke `http://localhost:3000/sandbox?rid=RID` (internal), bukan lewat iframe.
2. `default-src 'none'` di `/sandbox` memblokir `fetch()` langsung, jadi payload mensubmit form GET dengan `target=flagwin` ke `/api/flag`, membuka jendela auxiliary same-origin.
3. Setelah 500ms, `open('', 'flagwin')` mengambil kembali window tersebut, `document.body.innerText` membaca JSON respons, lalu top-level navigation mengirim data ke endpoint `/leak?data=...` attacker.

**Pelajaran:** CSP berbasis nonce tidak jadi trust boundary kalau attacker mengontrol `src` script yang sudah punya nonce server; sandbox berbasis iframe percuma jika resource yang sama bisa dibuka langsung sebagai top-level document; memblokir `connect-src` saja tidak cukup selama primitif navigasi/form-target masih tersedia.

---
