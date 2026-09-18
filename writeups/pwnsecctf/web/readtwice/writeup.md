# readtwice

**Kategori/Event:** Web — PwnSec CTF 2026 · CTF.ae · **Kesulitan:** Hard · **Flag:** `pwnsec{1503fc99f750c466}`

**Tujuan:** membaca dokumen terproteksi dua kali (nama challenge menyiratkan bypass mekanisme "read once").

**Inti kerentanan:**
- `/create` memvalidasi DOM akhir memakai Chromium offline **dengan JavaScript dimatikan**, sementara `/sandbox` merender note yang sama dengan CSP `sandbox allow-scripts` dan **JavaScript aktif** saat direview sungguhan. Perbedaan parsing ini dieksploitasi lewat kombinasi *Declarative Partial Updates* processing instruction dan perbedaan parsing `noscript` di dalam **declarative shadow DOM**:
  - Saat divalidasi (JS mati): DOM tereduksi jadi satu meta CSP + satu `div` kosong (tampak aman).
  - Saat direview sungguhan (JS aktif): script eksternal `/s.js` sempat **berjalan sebelum meta CSP diterapkan**.
- Script tersebut mentransfer `MessagePort` iframe review ke window attacker, yang mengirim `ready` sehingga `/complete` menandai state approved.
- Navigasi cross-site biasa gagal karena `Sec-Fetch-Site: cross-site`. Solusinya: dokumen attacker bernavigasi ke `about:blank`, lalu helper same-origin memanggil `opener.history.back()`. Karena entry aslinya `Cache-Control: no-store`, Chromium meminta ulang ke server dengan header `Sec-Fetch-Site: none` — dan response kedua ini melakukan **redirect 302** ke `http://localhost:3000/reports/check?rid=...`, tetap mempertahankan header tersebut dan cookie admin `Lax`.
- Request navigasi ini sendiri men-set flag `finalized` di watcher server, sehingga endpoint mengembalikan note mentah (raw) — script di dalamnya membaca `/api/flag` dan mengirim ke callback.

**Pelajaran:** perbedaan pengaturan JavaScript antara tahap validasi DOM dan tahap eksekusi sungguhan bisa menciptakan *parser differential* yang berbahaya; Fetch Metadata (`Sec-Fetch-Site`) bukan trust boundary yang cukup ketat kalau history traversal dan redirect bisa menghasilkan nilai `none` sambil tetap membawa cookie sesi yang dibutuhkan.

---

## Pola & Benang Merah Umum

Beberapa pelajaran lintas-challenge yang berulang di seri PwnSec CTF 2026 kategori web ini:

1. **CSP/sandbox bukan trust boundary absolut** — muncul di *easy-leak* (CSP hanya di proxy), *readonce* & *readonce-revenge* (bypass CSP nonce/opaque sandbox), dan *readtwice* (parser differential mengalahkan sandbox).
2. **`Sec-Fetch-*` dan `SameSite=Lax` sering disalahpahami sebagai proteksi kuat** — pada kenyataannya navigasi top-level, redirect, dan history traversal masih bisa memenuhi syarat header tersebut sambil membawa cookie sesi (readonce-revenge, readtwice, Neon Skies via urutan cookie).
3. **Sanitizer DOM (DOMPurify) tidak menjamin aman dari library pihak ketiga** yang membaca atribut sebagai konfigurasi eksekusi kode (mouse in the house).
4. **Validator/parser yang longgar terhadap error** bisa membuka celah eksekusi kode berbahaya sebelum atau tanpa terdeteksi validator (pickle, PHault via tipe return `mysqli::query()`).
5. **Reference window (`event.source`, `WindowProxy`) tetap bisa didapat lewat `postMessage`** meski `opener` sudah diputus — dipakai di *mouse in the house* dan menjadi bagian pola serupa di *readonce-revenge*.

---

*Dokumen ini disusun berdasarkan file `writeup/en.md` pada masing-masing folder challenge di dalam `web.zip` yang diunggah.*
