# PHault

**Kategori/Event:** Web — PwnSec CTF 2026 · **Kesulitan:** tidak dicantumkan · **Flag:** `pwnsec{74f8b0da59cbf20c}`

**Tujuan:** membaca isi tabel `flag` lewat SQL Injection blind, walau response teks dan waktu eksekusi dinormalisasi (shutdown handler memaksa total waktu ≥2 detik untuk semua path, sukses maupun gagal).

**Inti kerentanan:** parameter `id` dikonkatenasi langsung ke query MySQL. Oracle Boolean/timing biasa tidak berguna karena teks dan waktu response disamakan. Tapi ditemukan oracle baru: `SELECT ... INTO @var` membuat `mysqli::query()` mengembalikan `boolean true`, bukan objek result — sehingga panggilan `fetch_row()` berikutnya menghasilkan **PHP fatal error**.

**Payload inti:**
```sql
0 OR IF((<kondisi>),1,0) INTO @phault
```
- Jika kondisi **true** → subquery mengembalikan >1 baris → SQL error → masuk cabang `die()` eksplisit.
- Jika kondisi **false** → 0 baris → query sukses tapi `fetch_row()` gagal → fatal error PHP.

Dua respons ini punya panjang byte berbeda (4557 vs 4744 byte) sehingga bisa dibedakan secara reliabel — inilah oracle 1-bit yang dipakai untuk ekstraksi data.

**Alur eksploitasi:** solver melakukan binary search panjang flag, lalu binary search `ORD(SUBSTRING(...))` per karakter (0–255) dengan hingga 8 posisi diproses paralel, target akhir `(SELECT flag FROM flag LIMIT 1)`.

**Pelajaran:** meski response dinormalisasi, celah SQLi blind masih bisa bocor lewat *tipe return* query dan bagaimana API PHP berikutnya bereaksi terhadap tipe tersebut.

---
