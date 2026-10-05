---
ctf: "Anti-Slop CTF 2026"
kategori: "Cryptography"
challenge: "Polynomial Drift"
flag: "slopped{polyphase_masks_force_a_hidden_number_pivot}"
teknik: "Kebocoran 24 bit rendah nonce ECDSA lewat preview byte VM; Hidden Number Problem diselesaikan sebagai CVP lattice dengan fpylll atas 11 signature"
---

# Polynomial Drift — Anti-Slop CTF 2026 (Crypto, 443 poin)

## Deskripsi Singkat

Servis TCP Rust menandatangani capsule commit dengan ECDSA di atas secp256k1, tapi VM yang menjalankan tiap capsule membocorkan 24 bit rendah nonce penandatanganan. Sebelas signature plus solve CVP dengan `fpylll` memulihkan private key.

## Analisis

Untuk capsule yang mendorong integer `(1, 2, 3, 4)` ke stack VM, 24 bit rendah nonce ECDSA sama dengan `(4 << 16) | (3 << 8) | preview_byte`, di mana `preview_byte` dikembalikan di respons. Itu kebocoran 24-bit-per-signature pada kurva 256-bit — jauh di dalam rezim Hidden Number Problem.

**Bagaimana lattice HNP-nya bekerja.** ECDSA memberi `k_i = z_i/s_i + (r_i/s_i)·d (mod n)`. Pecah `k_i = K_i + 2^24·t_i` di mana `K_i` adalah 24 bit rendah yang diketahui. Maka `2^24·t_i ≡ a_i·d + b_i (mod n)`. Unknown-nya adalah `d` (dibagi bersama) dan satu `t_i` per signature (masing-masing ~232 bit, jauh lebih kecil dari `n`). Ini adalah CVP pada lattice berdimensi `(m+1)` yang bisa diselesaikan `fpylll` BKZ-20 dengan `m = 11` signature.

**Kenapa 11 signature cukup untuk secp256k1?** Threshold sukses HNP kira-kira `signatures × leaked_bits > 2n`. Untuk secp256k1, `2n = 512`. Dengan 24 bit bocor per signature kamu butuh ~22 signature di batas naif, tapi lattice-nya biasanya berhasil jauh di bawah itu. Sebelas cukup dalam praktiknya — keseimbangan antara waktu koleksi dan dimensi lattice (yang membebani waktu reduksi). Tambahkan beberapa signature ekstra kalau percobaan pertama menemukan tanda `d` yang salah.

**Kenapa diag key adalah umpan.** Endpoint diag menandatangani payload status dengan key terpisah yang nonce-nya terlihat acak. Tidak ada kebocoran di jalur itu. Jalur commit-signing memakai key utama dan membawa kebocoran VM-preview. Challenge-nya dirancang menghargai attacker yang memilih target yang tepat — solve pass-pertama menghabiskan 40 menit menyerang diag sebelum pivot ke target yang benar.

## Eksploitasi / Solusi

Kumpulkan 11+ signature dari jalur commit-signing, bangun CVP lattice, selesaikan dengan `fpylll`, pulihkan private key, verifikasi, lalu tandatangani auth challenge:

```
slopped{polyphase_masks_force_a_hidden_number_pivot}
```

## Catatan / Insight

**Kebocoran nonce parsial adalah kompromi kunci penuh.** Polynomial Drift membocorkan 24 dari 256 bit nonce per signature — jauh di bawah threshold historis 8-bit-per-signature untuk serangan HNP pada kurva 256-bit. Tool lattice modern (`fpylll`, BKZ-20) menangani kebocoran 24-bit dalam 11 signature tanpa berkeringat. Di mana pun `k` milik ECDSA diturunkan dari sesuatu yang bisa diamati (counter per-panggilan, session ID, timestamp, byte preview VM), asumsikan key-nya bisa dipulihkan dari signature sejumlah polinomial. Threshold-nya terus menurun seiring lattice reduction makin matang.

**Permukaan "diagnostik" jarang jadi bug-nya.** Diag key milik Polynomial Drift adalah umpan. Auditor harus mengikuti alur data ke endpoint yang digerbangi dan mencari kebocoran termurah di jalur itu, bukan di jalur diagnostik. Umpan menghabiskan waktu.

## Flag

```
slopped{polyphase_masks_force_a_hidden_number_pivot}
```
