---
ctf: "Anti-Slop CTF 2026"
kategori: "Blockchain (Bridge Protocol, bukan EVM)"
challenge: "Finality Cache"
flag: "slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}"
teknik: "Bridge receipt forge — patch tiga field konsisten (lane varint, header amount, VM commitment), rekomputasi commitment lewat binary guardian sendiri di bawah gdb"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/blockchain"
---

# Finality Cache — Anti-Slop CTF 2026 (Blockchain, 447 poin)

**Catatan:** "blockchain" di sini berarti *protokol bergaya bridge dengan commitment custom*, bukan smart contract Solidity. Tidak ada Solidity, Foundry, atau EVM. Kedua challenge mengirim binary custom yang berperan sebagai servis guardian/relayer. Bug-nya ada di bagaimana guardian itu memvalidasi dan mengonsumsi byte, bukan di kontrak on-chain mana pun.

## Deskripsi Singkat

Bridge receipt-forge: edit jumlah klaim, edit jumlah header, rekomputasi VM commitment agar cocok, redeem klaim bernilai tinggi.

## Analisis

Bridge receipt-nya punya tiga field yang harus tetap konsisten: **lane varint** yang meng-encode jumlah klaim, **amount ter-committed little-endian** milik header, dan **VM commitment** 32-byte atas program lane. Guardian merekomputasi commitment ini secara lokal. Karena rutin commitment-nya hidup di dalam binary guardian tanpa MAC key atau signature upstream, siapa pun yang memegang binary-nya bisa merekomputasinya sendiri. Patch ketiga field secara konsisten dan receipt-nya tervalidasi.

**Kenapa guardian merekomputasi commitment secara lokal?** Guardian bridge harus memvalidasi receipt yang diproduksi sistem upstream. Bug-nya bukan rekomputasi lokal itu sendiri; bug-nya adalah rekomputasi lokal itu **satu-satunya** pengecekan. Kalau commitment tertanam itu juga ditandatangani oleh validator chain upstream dengan public key yang dipatok, rekomputasi lokal akan jadi sanity check dan signature-nya jadi gerbang keamanan sungguhan. Sebagaimana dikirimkan, guardian ini mengaudit receipt terhadap dirinya sendiri.

## Eksploitasi / Solusi

Dua pendekatan untuk merekomputasi VM commitment: reimplementasi rutin commitment-nya di Python (butuh berjam-jam reversing untuk hash bergaya sponge dengan personalisasi custom), atau **biarkan guardian menghitungnya untukmu di bawah `gdb`**. Pendekatan `gdb` lebih cepat: pasang breakpoint di alamat rekomputasi (`0x401a7a`), suplai receipt yang sudah di-patch, single-step sampai digest-nya ada di register atau stack, dump 32 byte-nya, tempel kembali di offset receipt `0x3c..0x5b`.

```
slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}
```

## Catatan / Insight

**Pelajaran untuk defender:** rekomputasi lokal hanya mengautentikasi kalau kunci rekomputasinya tidak tersedia bagi attacker — artinya butuh signature sungguhan dari chain upstream atau MAC key yang tidak diekspos guardian. Protokol bridge yang mengandalkan "commitment lokal cocok dengan apa yang baru saja kuterima" tanpa signature independen sedang mengaudit datanya sendiri.

## Flag

```
slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}
```
