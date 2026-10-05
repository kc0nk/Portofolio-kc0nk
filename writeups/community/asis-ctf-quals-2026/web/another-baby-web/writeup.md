---
ctf: "ASIS CTF Quals 2026"
kategori: "Web"
challenge: "Another Baby Web!"
flag: "ASIS{Baby_w3b_cha!!3nGe_$$$}"
teknik: "Path filter one-pass replace('../','') dilewati '....//' ; content filter bypass lewat Range header; path flag ditemukan dengan membaca plocate.db lewat LFI yang sama"
sumber: "https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Web/AnotherBabyWeb"
---

# Another Baby Web! — ASIS CTF Quals 2026 (Web, Baby)

## Deskripsi Singkat

Aplikasinya Flask dua-route. `GET /` mengembalikan source aplikasi sendiri; `GET /inspect?path=...` membaca file dari disk di balik tiga pengecekan: `resolve()`, `bad_data()`, `is_forbidden()`. Satu di antaranya adalah pengalih perhatian, dua lainnya bisa di-bypass.

## Analisis

**Bug 1 — traversal lewat `replace` one-pass.** `resolve()` membuang `../` tepat sekali, lalu menyerahkan string-nya ke `os.path.normpath("/app" + cleaned)`. `....//` menyisakan `../` setelah replacement tunggal: `"/....//x"` → `replace("../","")` → `"/../x"` → `normpath("/app/../x")` → `"/x"`. Jadi `path=/....//<abs>` membaca `/<abs>` di luar web root `/app`. Dikonfirmasi dengan membaca `/root/.bashrc` — yang membutuhkan bit `+x` di `/root` bermode `0700`, membuktikan aplikasi berjalan sebagai **root**.

**Bug 2 — content filter adalah pengecekan body, jadi `Range` mengalahkannya.** `bad_data()` memeriksa byte yang dikembalikan. File flag (`ASIS{...}`) diblokir, tapi `send_file(..., conditional=True)` memproses header HTTP `Range` dan aplikasi membaca ulang body yang **sudah di-range**. Meminta `Range: bytes=4-` mengembalikan flag tanpa prefix `ASIS`-nya, yang lolos filter. Tiga konsekuensi: lewati substring terblokir dengan ranging di sekitarnya; window melewati cap 64 KiB dengan membaca slice ≤60 KiB; dan **oracle keberadaan eksak**: `Range: bytes=0-0` mengembalikan satu byte, yang tidak pernah bisa mengandung `ASIS` (4 byte) atau `lib` (3 byte), jadi `200 jika dan hanya jika file ada` tanpa peduli isinya.

**Non-bug — `is_forbidden` kedap.** `is_forbidden` berjalan pada string yang sudah ter-normpath-kanonik, dan satu-satunya cara leksikal membuka file terlarang sambil menghindari pengecekan adalah leading double-slash — tapi `resolve()` selalu membangun `os.path.normpath("/app" + …)`, hasilnya selalu diawali satu `/`. Pencarian offline eksaustif mengonfirmasi **nol** bypass. `/entrypoint.sh` dan `/proc/self/environ` adalah jalan buntu — pengalih perhatian yang disengaja.

**Menemukan path flag sungguhan.** Dua flag umpan adalah satu-satunya file `flag.txt` di mana pun. Membaca `/var/log/dpkg.log` menunjukkan box-nya **Ubuntu 24.04** dengan **`plocate` sengaja diinstal** plus `plocate-updatedb.timer`. `plocate` memelihara `/var/lib/plocate/plocate.db`, index filesystem penuh. `updatedb` berjalan setelah flag ditempatkan, jadi DB-nya tahu path tersembunyi.

**Menarik database 333 KB lewat LFI.** DB-nya lebih besar dari 64 KiB, dan sebagai binary kadang mengandung urutan byte `lib`/`ASIS`. Baca dalam window ≤60 KiB; kapan pun window mengembalikan 400, rekursi dengan membagi dua. Byte tunggal tidak bisa memicu filter, jadi rekursinya selalu berakhir di byte sungguhan. Total: ~176 request.

**Parsing plocate.db.** Header-nya memberi setiap field yang dibutuhkan (magic, `num_docids=287`, `filename_index_offset`, `zstd_dictionary_length=1024`, `zstd_dictionary_offset`). Index filename-nya adalah offset `uint64` little-endian, masing-masing menunjuk **frame zstd terkompresi dengan dictionary tertanam**. Mendekompresi setiap frame dengan `zstd -D <dict>` menghasilkan **9178** path absolut terpisah-NUL. Memfilter untuk `flag` mengungkap entri ketiga, non-umpan: `/app/811dd3cd18605ed6761d0466f47023d4/flag.txt`.

## Eksploitasi / Solusi

Path-nya ada di bawah `/app`, jadi `/inspect` menjangkaunya langsung; `Range: bytes=4-` melewati prefix `ASIS` dari `bad_data()`:

```bash
$ curl -s 'http://.../inspect?path=/811dd3cd18605ed6761d0466f47023d4/flag.txt' \
        -H 'Range: bytes=4-'
{"content":"e0JhYnlfdzNiX2NoYSEhM25HZV8kJCR9"}       # {Baby_w3b_cha!!3nGe_$$$}
```

```
ASIS{Baby_w3b_cha!!3nGe_$$$}
```

## Catatan / Insight

- **Path sanitization berbasis string-blacklist bukan kanonikalisasi.** `replace("../", "")` one-pass trivial dikalahkan (`....//`); normalisasi dengan `realpath` dan verifikasi hasilnya berada **di dalam** root yang dimaksud.
- **Content filter hidup di bawah feature set `send_file`.** Dengan `conditional=True`, `Range` (dan `If-Range`, `If-Modified-Since`) membentuk-ulang body *sebelum* aplikasi memeriksanya. Memblokir byte di respons bukan access control.
- **Security-by-obscurity gagal melawan file index.** Direktori flag bernama-acak tidak berharga begitu `plocate`/`mlocate`/`locate` bisa dibaca; jangan kirimkan indexer yang mengkatalogkan rahasiamu.
- **Memblokir `/proc` dan `/entrypoint.sh` tidak berpengaruh di sini** — kebocorannya adalah database world-readable biasa. Pertahanan harus mencakup seluruh filesystem yang bisa dibaca, bukan denylist pilihan tangan.

## Flag

```
ASIS{Baby_w3b_cha!!3nGe_$$$}
```
