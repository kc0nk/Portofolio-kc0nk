---
ctf: "Anti-Slop CTF 2026"
kategori: "Pwn (Binary Exploitation)"
challenge: "Graceful Exit"
flag: "slopped{previewed_offsets_can_reseal_reports}"
teknik: "Back-reference bertanda-negatif di VIEW preview membocorkan pointer flag; overwrite objek plan 0x80-byte lewat copy nama simbol SYMS record mengalihkan fetch ke pointer bocoran"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/pwn"
---

# Graceful Exit — Anti-Slop CTF 2026 (Pwn)

## Deskripsi Singkat

Dua bug independen yang saling melengkapi. Engine preview VIEW menerima offset back-reference bertanda (termasuk nilai negatif), yang memungkinkan menyalin byte dari **sebelum** buffer preview — termasuk blok seed 16-byte yang berisi pointer ter-obfuskasi-XOR ke halaman flag dan panjang flag-nya. Terpisah dari itu, jalur SEAL menyalin nama simbol sebuah record SYMS di atas objek plan 0x80-byte, memungkinkan attacker menimpa `report_ptr` (offset `0x38`), `report_len` (offset `0x40`), `cookie` (offset `0x30`), dan flag `finished` (offset `0x7c`) milik plan.

## Analisis

**Menggabungkan keduanya:** bocorkan pointer flag lewat back-reference negatif, timpa plan dengan pointer itu, lalu panggil `fetch` untuk membaca lewat jalur output normal.

**Kenapa nonce GORF penting untuk CRC seed?** Frame sebelum `hello` memakai CRC seed tetap (`0x714a5c21`). Respons `hello` mengandung token `nonce=<8 hex digit>` yang menjadi CRC seed untuk setiap frame berikutnya. Kalau exploit-mu terus memakai seed pre-`hello` setelah handshake, setiap frame berikutnya mengembalikan "bad crc" dan kamu akan membuang waktu memburu bug yang tidak ada. Parse nonce-nya, tukar seed-nya, baru kirim frame exploit-mu.

## Eksploitasi / Solusi

1. Kirim frame VIEW dengan offset back-reference negatif untuk membaca sebelum buffer preview, mengekstrak blok seed 16-byte (pointer flag ter-XOR + panjangnya).
2. XOR-decode pointer flag-nya.
3. Kirim frame SEAL dengan record SYMS yang nama simbolnya di-craft untuk menimpa `report_ptr` plan dengan pointer flag hasil bocoran (plus `report_len`, `cookie`, `finished` yang sesuai).
4. Panggil `fetch` — jalur output normal sekarang membaca dari pointer flag.

```
slopped{previewed_offsets_can_reseal_reports}
```

## Catatan / Insight

**Pelajaran untuk defender:** offset back-reference yang diterima dari client harus divalidasi non-negatif dan dalam batas buffer — offset bertanda yang lolos tanpa pengecekan magnitude adalah primitive read-arbitrary yang menyamar sebagai fitur "preview". Copy nama simbol yang panjangnya tidak divalidasi terhadap ukuran struct tujuan adalah overflow buku-teks; struct tujuan (di sini objek plan 0x80-byte) harus dijaga dengan bound check eksplisit, bukan diasumsikan cukup besar.

## Flag

```
slopped{previewed_offsets_can_reseal_reports}
```
