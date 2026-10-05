---
ctf: "Anti-Slop CTF 2026"
kategori: "Pwn (Binary Exploitation)"
challenge: "Anchorpoint"
flag: "slopped{shadow_quote_ghash_rootcapsule}"
teknik: "Rantai 5-tahap: overflow VM 4-byte membuka gate state → nonce ECDSA affine bocor → BIP340 shadow proof → nonce reuse GCM membocorkan H dan E_K(J0) → forge tag root capsule"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/pwn"
---

# Anchorpoint — Anti-Slop CTF 2026 (Pwn, 448 poin)

## Deskripsi Singkat

Lima primitive yang tersusun bersama: overflow opcode VM `0x50` menulis melewati buffer 64-byte ke state yang bersebelahan, ECDSA quote dengan nonce affine membocorkan kunci, shadow proof bergaya BIP340, dan nonce seal GCM yang dibekukan memungkinkan forge GHASH dua-blok berperan sebagai root capsule. Ini contoh paling jernih dari bug memory-corruption yang dipakai murni sebagai **pembuka state machine**, bukan sebagai primitive control-flow.

## Analisis

**Tahap 1 — Overflow VM 4-byte.** Opcode VM `0x50` menulis melewati buffer respons 64-byte ke dalam state server yang bersebelahan, membuka empat gate hilir: budget quote, unlock shadow, budget capsule, dan freeze seal-nonce. Kenapa cuma butuh 4 byte? Empat byte state yang bersebelahan yang dibutuhkan (budget quote, unlock shadow, budget capsule, freeze seal-nonce) semuanya kebetulan hidup di dalam struct kecil yang sama yang mengikuti buffer respons di memori. Menulis 68 byte bernilai `1` mencakup keempat offset sekaligus. Offset persisnya berasal dari reversing struct buffer-respons di binary; layout-nya stabil lintas koneksi karena allocator menempatkan struct itu di arena yang sama tiap kali.

**Tahap 2 — Pemulihan kunci quote.** Dengan QUOTE terbuka, signer ECDSA membocorkan empat signature yang nonce-nya mengikuti recurrence affine `k[i+1] = a·k[i] + b`. Recurrence ini tereduksi jadi persamaan kuadratik dalam `d` yang bisa diselesaikan modulo group order secp256k1.

**Tahap 3 — Shadow proof BIP340.** Dengan kunci quote yang sudah dipulihkan, shadow proof bergaya BIP340 bisa ditandatangani.

**Tahap 4-5 — Forge GHASH lewat nonce reuse GCM.** Nonce seal GCM yang dibekukan memungkinkan dua capsule dengan AAD-sama nonce-sama membocorkan `H^2` dan `E_K(J0)` lewat serangan GHASH standar, memungkinkan forge tag pada AAD root capsule.

**Bagaimana nonce reuse AES-GCM membocorkan hash subkey.** Untuk dua ciphertext GCM satu-blok `C_0` dan `C_1` yang di-seal di bawah nonce sama dan AAD sama: `tag_0 XOR tag_1 = (C_0 XOR C_1) * H^2` di GF(2^128), karena suku `E_K(J0)` saling mencoret dan kontribusi AAD-nya identik. Membagi memberi `H^2`; akar kuadrat di GF(2^128) adalah `(H^2)^(2^127)` karena squaring adalah automorfisme. Dengan `H`, hitung `E_K(J0) = tag_0 XOR GHASH(H, AAD_0, C_0)`, lalu forge tag untuk `(AAD', C')` baru mana pun di bawah nonce yang sama.

## Eksploitasi / Solusi

Rantai lengkap dalam satu koneksi:

1. Kirim capsule overflow untuk membuka semuanya.
2. Kumpulkan empat quote, pulihkan private key quote, verifikasi terhadap public key.
3. Hitung pesan shadow, tandatangani dengan kunci hasil pemulihan, submit shadow proof.
4. Submit dua capsule satu-blok di bawah nonce GCM beku dengan AAD identik dan plaintext yang diketahui.
5. Pulihkan `H` dan `E_K(J0)` dari kedua tag.
6. Hitung tag hasil forge untuk root capsule `(rootcaps|epoch|counter_byte, root_ciphertext)`.
7. Submit root capsule, lalu request FLAG.

```
slopped{shadow_quote_ghash_rootcapsule}
```

## Catatan / Insight

**Pelajaran untuk defender:** memory corruption di servis modern jarang jadi bug kontrol-RIP langsung. Ia jadi pembuka untuk permukaan kriptografi atau state-machine di balik layer memori. Ketiga challenge di track pwn event ini menghukum solver yang terpaku pada "temukan overflow-nya, tulis shellcode". Flag sungguhannya di setiap kasus butuh memodelkan state machine, mengidentifikasi transisi mana yang dibuka korupsi memorinya, lalu mengomposisikan transisi yang terbuka itu dengan kelemahan kriptografi apa pun yang dikirimkan protokolnya. Exploit chain di 2026 terlihat lebih seperti forge protokol multi-langkah dibanding stack-smash-dan-pivot klasik.

## Flag

```
slopped{shadow_quote_ghash_rootcapsule}
```
