# Neon Skies

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** Medium · **Flag:** `pwnsec{7f655c6d59355727}`

**Tujuan:** mencuri cookie `FLAG` (HttpOnly) milik bot admin.

**Inti kerentanan:**
- Cookie `FLAG` tidak memakai prefix `__Host-`, sehingga origin lain di `*.chal.ctf.ae` bisa membuat cookie **sama nama** dengan `Domain=chal.ctf.ae`.
- Browser mengirim cookie dengan path lebih panjang lebih dulu, dan di antara path yang sama, cookie yang lebih lama dulu.
- Crystal 1.18.2 (`HTTP::Cookies#<<`) menyimpan cookie ke dalam Hash berdasarkan nama, sehingga **nilai terakhir yang menang** saat parsing cookie duplikat pada request `/admin`.
- `admin.ecr` menaruh nilai cookie `FLAG` ke HTML **tanpa escaping**, sehingga nilai attacker yang menang dieksekusi sebagai XSS (`<svg/onload=...>`).

**Alur eksploitasi:**
1. Menggunakan origin sibling dari challenge lain (`mouse in the house`) yang punya gadget dynamic-import PrismJS untuk menaruh cookie `Domain=chal.ctf.ae` bernama `FLAG` berisi payload XSS, di dua path (`/admin` dan `/`).
2. Saat bot mengunjungi `/admin`, urutan cookie membuat payload attacker yang dirender di HTML, bukan cookie asli.
3. Payload XSS menghapus kedua cookie `Domain=chal.ctf.ae`, lalu `fetch()` ulang ke `/admin`. Kali ini cookie host-only asli (yang HttpOnly, tak terlihat oleh `document.cookie`) tetap dikirim oleh browser dan dirender ke response — flag pun bisa dibaca dari body response.

**Pelajaran:** gunakan prefix `__Host-` untuk cookie sensitif; jangan bergantung pada urutan cookie duplikat; tetap lakukan output encoding untuk nilai cookie; `HttpOnly` tidak melindungi dari refetch response via same-origin XSS.

---
