---
ctf: "boroCTF 2026"
kategori: "Forensics"
challenge: "slack"
flag: "boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}"
teknik: "Image ext4 10 MB berisi 500 file kecil; data penting ada di block slack space; blkls -s mengekstrak dan flag adalah byte non-nol"
sumber: "https://github.com/Abdelkad3r/boroCTF-2026"
---

# slack — boroCTF 2026 (Forensics)

## Deskripsi Singkat

Satu-satunya soal forensics dalam event ini. Sebuah image filesystem ext4 berukuran 10 MB. Di dalamnya ada 500 file bernama `entry_log_N.txt` (N ganjil) dan `exit_log_N.txt` (N genap) untuk `N = 1..500`, masing-masing berisi sampah karakter random yang bisa dicetak (uniform pada karakter 33–126). Nomor inode-nya adalah `N + 11` di setiap file.

## Recon

Permukaan soal ini dirancang agar terlihat seperti perburuan covert-channel. Per file ada ukuran (10–100 byte), generation ID, access-time dalam nanosecond, dan pola penamaan entry-vs-exit. Setiap satu dari elemen ini terlihat seperti mungkin mengkodekan sebuah bitstring. Ternyata tidak satu pun benar.

**Kanal-kanal yang TIDAK membawa flag.** Dieliminasi secara eksplisit:

| Kanal | Hasil |
|---|---|
| Bitstring urutan direktori | Noise |
| Access-time ns yang dikuantisasi | Tidak ada pola |
| Field generation inode | Tidak ada pola |
| Ukuran file mod bilangan prima kecil | Tidak ada pola |
| Paritas nama file (entry vs exit) | Tidak ada pola |
| Flag `xattr` / immutable / extent | Semuanya default |

Inti dari soal ini bergantung pada solver yang berhasil mengeliminasi semua kemungkinan di atas. Flagnya bukan di metadata per-file mana pun — flag ada di lapisan filesystem, di bawah level file itu sendiri.

## Analisis — Kanal Sebenarnya: Block Slack

ext4 mengalokasikan ruang dalam blok 4 KB. Setiap file di handout hanya berisi 10–100 byte. Setiap blok yang teralokasikan punya sekitar 4 KB ruang sisa yang tidak terpakai di bagian ekor (slack). Tool `blkls -s` dari Sleuth Kit mengekstrak persis bagian ini:

```bash
blkls -s chal.img > slack.bin
```

Ini menghasilkan 2.048.000 byte data slack (500 file × 4096 byte). Dari jumlah itu, tepat 36 byte non-nol yang bertahan, dan membacanya secara berurutan (offset order) mengeja flagnya:

## Eksploitasi / Solusi

```bash
tr -d '\0' < slack.bin
# boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}
```

## Catatan / Insight

"Could you cut me some slack" (bisakah kau memberiku sedikit keringanan) cocok sempurna dengan judul soal ("slack" = ruang sisa). Pelajaran untuk defender di sini sama seperti yang selalu diajarkan komunitas forensik selama bertahun-tahun: **pada soal image filesystem, jalankan dulu ekstraksi slack/unallocated space**. `blkls -s` untuk slack dan `blkls -A` untuk unallocated space murah secara komputasi, cepat, dan bisa langsung menyingkirkan seluruh kategori "byte yang disembunyikan di ruang yang tidak sedang aktif dipakai filesystem" sebelum mengejar kanal-kanal metadata yang lebih eksotis.

## Flag

```
boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}
```
