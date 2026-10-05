---
ctf: "Anti-Slop CTF 2026"
kategori: "Blockchain (Bridge Protocol, bukan EVM)"
challenge: "Canopy Cache"
flag: "slopped{packbits_lookup_routes_rethread_the_owner_lane}"
teknik: "TOCTOU antar dua validator; dekompresi PackBits lolos cek panjang-input tapi menimpa bind table setelah bind tervalidasi, mengalihkan route ke image yang dikontrol attacker"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/blockchain"
---

# Canopy Cache — Anti-Slop CTF 2026 (Blockchain, 490 poin)

## Deskripsi Singkat

TOCTOU antara dua parser di validator berbeda, dieksploitasi lewat dekompresi PackBits yang menimpa bind table *setelah* bind-nya sudah tervalidasi.

## Analisis

Dua validator di bind table tidak sepakat: **bind decoder** menolak image offset di atas `0x0f`. **Route patcher** butuh offset di atas `0x17`. Bind langsung dengan offset yang diinginkan gagal validasi. Eksploitnya: dekompresi PackBits yang berjalan **setelah** sebuah bind jinak sudah tervalidasi, menimpa byte image-offset di bind table dari `0x05` (atau apa pun yang kamu pakai) jadi `0x18` (route warm-image). Route patcher membaca byte hasil mutasi dan menerimanya karena aturannya sendiri lebih longgar, dan invokasi audit lalu ter-route lewat image yang dikontrol attacker.

**Kenapa opcode `expand` PackBits tidak membatasi output-nya?** Opcode expand memvalidasi panjang input terkompresi tapi tidak panjang output hasil dekompresi. PackBits punya ekspansi worst-case 128× (satu byte literal plus satu byte kontrol `0x80` menghasilkan 128 byte output), jadi opcode mana pun yang hanya membatasi input terkompresi berisiko. Perbaikannya: batasi output terhadap ukuran buffer tujuan yang disuplai consumer, atau alokasikan tujuan dari region yang tidak bisa overlap dengan struktur tervalidasi mana pun.

**Kenapa `cap_mask = 0x01` penting?** Langkah "bless" menolak slot mana pun yang byte route-nya tidak punya `cap_mask & 0x01` yang di-set. Byte route yang di-stage attacker `02 01 01 01` di-decode jadi `[route_kind=2, quote_idx=1, cap_mask=0x01, flags=0x01]`. Hilangkan salah satu `0x01`-nya dan langkah bless menolakmu, memutus rantainya satu langkah sebelum flag.

**Memulihkan XOR stream sesi.** Sesi ini memakai LCG (`s_{i+1} = a·s_i + c mod m`) untuk menurunkan keystream XOR. Command `status` membocorkan satu atau lebih sampel state. Dengan konstanta publik `(a, c, m)` dari helper module, pulihkan seed dengan menjalankan LCG maju/mundur untuk sejajar dengan sampel yang bocor, lalu turunkan keystream untuk offset berikutnya. Ini bukan bug-nya; ini cuma plumbing protokol yang harus benar dulu sebelum sisa rantainya berfungsi.

## Eksploitasi / Solusi

```
slopped{packbits_lookup_routes_rethread_the_owner_lane}
```

## Catatan / Insight

**Pelajaran untuk defender:** validasi multi-tahap hanya berlaku kalau setiap consumer membaca snapshot kanonik yang **sama** dari input — artinya butuh logika kanonikalisasi bersama atau snapshot immutable pasca-validasi. Finality Cache mengajarkan "audit rekomputasi lokal"; Canopy Cache mengajarkan "audit celah TOCTOU antar validator." Protokol bridge produksi harus fokus pada kedua kelas ini secara default.

## Flag

```
slopped{packbits_lookup_routes_rethread_the_owner_lane}
```
