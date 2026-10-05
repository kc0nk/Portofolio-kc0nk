---
ctf: "R3CTF 2026 (r3kapig)"
kategori: "Web (ASP.NET)"
challenge: "mafuyuuuuu"
flag: "r3ctf{0tomE_K4iBOU-d3_@so6Ou-Yo_DokidoKl-sHit@1-J@N_Ka_dare_datte_congrats_finding_the_correct_solution0}"
teknik: "System.Random (xoshiro256**) dibagi antar endpoint post & debug ticket; pemulihan state via inversi bounded-reduction + meet-in-the-middle GF(2) atas 9 output"
sumber: "https://github.com/Abdelkad3r/R3CTF-2026/tree/master/web/mafuyuuuuu"
---

# mafuyuuuuu — R3CTF 2026 (Web / ASP.NET)

## Deskripsi Singkat

Servis template-rendering ASP.NET Core. Template engine-nya mengekspos fungsi `debug(ticket, command)` yang menjalankan shell command kalau `ticket` cocok dengan output `System.Random.Next(0, 2^31-1)` berikutnya. Instance `Random` yang sama juga dipakai `POST /api/desk/posts`, yang mengembalikan dua output RNG berurutan sebagai field `id` dan `csp`.

## Analisis

**Langkah 1 — Baca bug shared-RNG-nya.** `DebugLeaseService` men-share satu instance `Random` antara `IssuePostToken` dan `RunDebug`. Kalau kita bisa memulihkan state RNG dari kebocoran posts, kita bisa memprediksi ticket debug-nya. Template sandbox mengizinkan `debug` dan meloloskan `/readflag` lewat regex command (tanpa spasi, kurung kurawal, koma, kutip, atau metakarakter shell).

**Langkah 2 — Kumpulkan 160 output RNG hampir-berurutan.** `collect_posts.py` mem-pipeline 80 request `POST /api/desk/posts` lewat satu socket. Setiap respons membocorkan dua nilai `Random.Next(0, 2^31-1)` sebagai desimal ASCII base64-encoded. 160 output hampir-berurutan total.

**Langkah 3 — Modelkan xoshiro256** milik .NET 8.** Di .NET 8 x64, `System.Random` adalah `xoshiro256**`: `result = rotl(s1 · 5, 7) · 9 mod 2^64`. `Random.Next(0, 2^31-1)` mengambil 32 bit tertinggi dari `result` dan menerapkan reduksi ter-bound milik .NET. Solving SMT langsung atas generator penuh terlalu lambat. Pendekatannya: reduksi setiap nilai teramati jadi daftar kecil kemungkinan slice tengah dari `s1`, lalu selesaikan pilihannya dengan aljabar linier.

**Langkah 4 — Balikkan setiap kebocoran jadi 76 kemungkinan slice 34-bit dari s1.** Untuk setiap `v` teramati, balikkan reduksi integer ter-bound untuk mendapat kemungkinan nilai 32-bit tertinggi `x` dari output xoshiro. Mengupas balik perkalian dengan 9, membalik rotate, dan membalik relasi perkalian-dengan-5 memberi 76 kemungkinan slice 34-bit `s1[23..56]` per kebocoran.

**Langkah 5 — Meet-in-the-middle atas 9 output.** Transisi state xoshiro bersifat linier atas GF(2), jadi setiap bit dari setiap slice `s1[23..56]` masa depan adalah bentuk linier dalam state awal 256-bit. Untuk 9 output pertama: `9 × 34 = 306` persamaan, rank 256, menyisakan 50 dependensi paritas. Daripada `76^9 ≈ 10^17` kombinasi, `mitm9.cpp` melakukan MITM: bangun kontribusi paritas 50-bit untuk tiap kandidat slice tiap output, enumerasikan output 4-7 (76^4 ≈ 33M kombo), bucket syndrome XOR-nya berdasarkan 24 bit rendah, enumerasikan output 0-3 + output 8 (76^5 ≈ 2.5B kombo), cari syndrome nol yang cocok. Untuk setiap hit, angkat slice terpilih ke basis GF(2) dan validasi terhadap seluruh 160 output yang bocor.

**Langkah 6 — Tangani health probe.** `InternalHealthProbeService` mulai 3 detik setelah boot, memanggil `/healthz` tiap 5 detik, masing-masing mengonsumsi 3 nilai RNG. Pada saat solver selesai MITM (~20 detik) dan submit template debug, RNG sudah maju sejumlah kelipatan 3 yang tidak diketahui pasti. Sandbox mengizinkan sampai 48 ekspresi output per template. Tembakkan 48 percobaan debug dengan index prediksi `4*t`: panggilan `t` mengonsumsi index prediksi `3·t` (health probe) `+ t` (tick debug gagal sebelumnya) `= 4·t`. Salah satu dari 48 itu mendarat di posisi RNG saat ini yang benar dan mengeksekusi `/readflag`.

## Eksploitasi / Solusi

```
collected 160 values in 1.27s
mitm hits 22 at 19.97s
state 0x42e7c89e737017fb 0x225e34e6fd3fed 0x9a0243c9ae705551 0xa8a487047974e27a
...
r3ctf{0tomE_K4iBOU-d3_@so6Ou-Yo_DokidoKl-sHit@1-J@N_Ka_dare_datte_congrats_finding_the_correct_solution0}
```

## Catatan / Insight

Pelajarannya berlaku umum untuk setiap framework yang mengirimkan PRNG non-kriptografi yang cepat: `xoshiro256**` (.NET 8), `PCG64` (Python 3.11+), `xoshiro128++` (Java 17), semuanya dicampur dengan reduksi integer ter-bound kecil. State apa pun yang bisa di-serialize, bisa dipulihkan dari cukup banyak output publik, dan jalur kode mana pun yang memperlakukan output Random sebagai rahasia tak-terprediksi adalah serangan pemulihan-state yang menunggu terjadi. Pakai `RandomNumberGenerator` / `secrets.token_bytes` untuk apa pun yang menggerbangi otorisasi.

## Flag

```
r3ctf{0tomE_K4iBOU-d3_@so6Ou-Yo_DokidoKl-sHit@1-J@N_Ka_dare_datte_congrats_finding_the_correct_solution0}
```
