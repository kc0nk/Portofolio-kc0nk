---
ctf: "Anti-Slop CTF 2026"
kategori: "Cryptography"
challenge: "Sealed Signal"
flag: "slopped{cbc_mac_capsule_splice_last_claim_wins}"
teknik: "Chosen-message CBC-MAC oracle berbagi key dengan MAC resume-capsule; XOR-cancel header 16-byte tetap untuk menyambungkan MAC valid ke resume capsule role=root yang terlarang"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/crypto"
---

# Sealed Signal — Anti-Slop CTF 2026 (Crypto, 459 poin)

## Deskripsi Singkat

Relay WebSocket memakai CBC-MAC atas dua keluarga capsule yang kompatibel. Oracle penandatanganan cache menerima blob pilihan attacker, dan XOR-cancellation terhadap header cache 16-byte yang tetap menyambungkan MAC valid ke resume capsule terlarang.

## Analisis

Dua keluarga capsule (resume dan cache) berbagi key CBC-MAC yang sama. Penandatangan cache adalah **chosen-message oracle**: ia menghitung `MAC("CACHE::SIGNME::!" || attacker_blob)` untuk blob attacker mana pun (kecuali yang mengandung substring literal `scope=flag`). Header 16-byte tetap dimaksudkan untuk memisahkan kedua domain, tapi itu persis satu blok AES, jadi kontribusi CBC-MAC-nya adalah satu chaining state `H` yang bisa diukur attacker. Mengirim `B0 = P0 XOR H` mencoret `H` dalam chaining, dan mulai dari titik itu state output penandatangan cache cocok dengan state output MAC resume pada plaintext yang sama.

**Kenapa filter `scope=flag` tidak menghentikan splice-nya?** Filter-nya berjalan pada blob request penandatanganan-cache secara literal. Splice-nya tidak pernah meminta penandatangan menandatangani apa pun yang mengandung `scope=flag`; ia meminta penandatangan menandatangani `(P0 XOR H)`, lalu `(T1 XOR P2 XOR H)`, dst. Keduanya terlihat seperti blok pseudorandom di layer konten. Substring terlarangnya cuma muncul di plaintext resume-capsule yang dibangun splice-nya untuk MAC, yang tidak pernah dilihat penandatangan cache.

**Kenapa `admin` tidak cukup — kenapa gerbang flag butuh `root`?** State machine resume menerima beberapa string role dan melaporkan role yang di-resume kembali ke client. `admin` berhasil resume dan server mengonfirmasi `role=admin`. Tapi handler `FLAGREQ` mengecek spesifik `role=root`, bukan role "privileged" atau "admin-like" apa pun. Substitusi plaintext-nya lugas (ganti `role=admin` jadi `role=root` dan bangun ulang splice-nya dari nol), tapi ini jebakan nyata untuk percobaan pertama karena baris resumed-state-nya secara menyesatkan terlihat mengonfirmasi.

## Eksploitasi / Solusi

Plaintext target akhir:

```
P = b"kind=resume&role=root&scope=flag&room=flagroom&cache=flagroom&pad=AAAAAAAAAAAAA"
```

Panjang 80 byte, persis lima blok AES. Bangun splice-nya lewat dua query penandatanganan-cache, dapatkan MAC hasil forge, rakit capsule sebagai `P || forged_mac`, submit `RESUME(token=legit_token, capsule=forged_capsule)` diikuti `FLAGREQ()`. Token legitim dari sealing sebelumnya dipakai ulang; hanya capsule-nya yang berubah. Server menerima resume-nya (`resumed: root flag flagroom`), lalu `FLAGREQ` mengembalikan:

```
slopped{cbc_mac_capsule_splice_last_claim_wins}
```

## Catatan / Insight

Bug-nya adalah absennya domain-separation sungguhan antara capsule cache dan capsule resume. Keduanya memakai key AES yang sama di bawah konstruksi CBC-MAC yang sama. Header cache 16-byte tetap adalah satu-satunya hal yang menurut desainernya memisahkan kedua domain. Itu tidak berhasil, karena header-nya persis satu blok AES (kontribusinya satu chaining state `H` yang bisa diukur dengan satu query), chaining CBC-MAC linier terhadap XOR dari state dan blok berikutnya (attacker bisa meng-XOR-kan kontribusi `H` di blok mana pun berikutnya), dan dua query cache cukup untuk menyambung plaintext terlarang multi-blok apa pun.

Perbaikan yang benar adalah HMAC, yang memakai key-prefixing dengan cara yang tidak mengizinkan pencoretan semacam ini. Perbaikan kedua-terbaik adalah CMAC (NIST SP 800-38B), yang memakai dua subkey turunan untuk blok terakhir dan memutus interoperabilitas suffix-prefix yang membuat splice cache-ke-resume ini berhasil. Perbaikan minimum yang masih memakai CBC-MAC adalah menambahkan tag domain **rahasia** di depan setiap pesan sebelum di-MAC, sehingga tidak ada chosen-message oracle yang bisa memeriksa state setelah prefix itu.

**Pelajaran lebih luas:** oracle MAC chosen-message melintasi domain. Keberadaan penandatangan cache di key yang sama dengan MAC resume adalah bug-nya, terlepas dari filter apa pun yang diterapkan penandatangan cache. Filter itu adalah pengecekan *konten*; splice-nya terjadi di level *chaining-state*, di bawah konten yang dilihat filter. Pertahanan yang benar adalah menjaga key sepenuhnya terpisah (key AES berbeda untuk domain berbeda) atau memakai konstruksi MAC yang aman di bawah chosen message (HMAC, CMAC, GMAC dengan hygiene nonce yang benar).

## Flag

```
slopped{cbc_mac_capsule_splice_last_claim_wins}
```
