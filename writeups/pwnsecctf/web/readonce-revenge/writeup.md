# readonce-revenge

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** Hard · **Flag:** `pwnsec{917872750f693769}`

**Tujuan:** sama seperti *readonce*, tapi lebih diperketat: `/sandbox` kini pakai CSP `sandbox allow-scripts` (origin opaque), butuh manipulasi lebih kompleks.

**Inti kerentanan & alur (multi-tahap):**
1. `/review` menyimpan URL attacker di `currentReview.document`, membuka `/sandbox` dalam iframe, lalu menggantinya dengan dokumen `&end` setelah load pertama. Jika script attacker mengirim `top.postMessage()` saat event `pagehide` dokumen lama, `event.source` yang diterima adalah `WindowProxy` **lama** — beda dari `viewer.contentWindow` baru — sehingga parent mengira approval valid dan mengeset `approved=true`, mengirim `state` rahasia ke `/complete`.
2. Karena `/sandbox` bersifat opaque origin (`sandbox allow-scripts`), exploit tidak keluar dari origin tersebut secara langsung, melainkan:
   - Popup ke `/review` internal (top-level GET, membawa cookie admin `Lax`).
   - Tab asli bernavigasi ke `/sandbox?rid=...` internal — payload attacker sekarang jalan sebagai top-level sandbox.
   - **Service Worker** dipakai untuk membuat 40 dokumen sintetis (interval 10ms) demi **mengusir entry BFCache** dari check pertama (`history.go(-3)` biasa hanya mengembalikan dari BFCache, tak menyentuh server).
   - Dokumen sintetis terakhir menandai `sessionStorage.done` lalu `location.replace()` masuk ke sandbox internal.
   - Payload sandbox top-level memanggil `history.go(2-history.length)` untuk memilih entry check awal. Karena entry sudah tergusur dari BFCache, Chrome melakukan **request jaringan sungguhan** — response pertama mengubah varian cache `Vary: Cookie`, dan navigasi history menyediakan header Fetch Metadata `none/document` yang dibutuhkan.
3. Check kedua yang telah "approved" merender HTML note mentah tanpa escaping — stored XSS (<128 byte) memuat `final.js` yang membaca `/api/flag` via XHR sinkron dan mengirim ke callback sebelum navigasi lain menang balapan.

**Pelajaran:** `SameSite=Lax` tetap mengirim cookie pada navigasi top-level GET meski diblokir untuk fetch cross-site; sandbox opaque bisa "dibobol" secara struktural dengan memindahkan transisi privilege ke popup admin, menggusur BFCache pakai Service Worker, lalu menghidupkan kembali entry history sebagai request jaringan; pertahanan URL sekali-pakai (one-time URL) harus mempertimbangkan `Cache-Control: no-store`, history, dan perilaku BFCache — bukan cuma Fetch Metadata dan nonce.

---
