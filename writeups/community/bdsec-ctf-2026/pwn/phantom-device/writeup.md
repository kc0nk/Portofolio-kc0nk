---
ctf: "BDSec CTF 2026"
kategori: "Pwn (Binary Exploitation)"
challenge: "Phantom Device"
flag: "BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}"
teknik: "Duplicate-handle tidak increment refcount; release-handle memakai refcount → UAF; grooming tcache 0x110 bin mengoverlap handle device lama dengan objek session baru"
---

# Phantom Device — BDSec CTF 2026 (Pwn, 100 poin)

## Deskripsi Singkat

ELF Linux menu-driven yang mensimulasikan interface driver dengan device handle, duplicated handle, dan session object. Objek device maupun session sama-sama teralokasi sebagai chunk `calloc` 0x100-byte.

## Analisis — Bug-nya

Duplicate-handle menyalin descriptor ke slot descriptor kosong pertama dan menandainya aktif, **tapi tidak increment refcount objek device-nya**. Release-handle memakai refcount, jadi me-release descriptor asli menurunkannya ke 0 dan membebaskan chunk di bawahnya; descriptor duplikat masih lolos gerbang active/type dan sekarang menunjuk ke chunk yang sudah dibebaskan — primitive **use-after-free**.

## Eksploitasi / Solusi

**Grooming**: alokasikan dan bebaskan tujuh device pengisi untuk mengisi tcache bin `0x110`, alokasikan device target, duplikasikan, release yang asli — `calloc(1, 0x100)` berikutnya untuk session sekarang memakai ulang chunk itu. Handle device yang stale kini overlap dengan session di offset 0.

Baca header session, parse `(uid, nonce, checksum1, checksum2)`, pulihkan cookie:

```
cookie = ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) ^ uid
```

Lalu tulis `role = 0x1337133713371337` plus checksum2 yang terkoreksi:

```
checksum2 = rol64(nonce, 11) ^ cookie ^ rol64(uid + 0x5478547854785478, 29)
```

Menu opsi 8 membuka `flag.txt`.

```
BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}
```

## Catatan / Insight

**Prinsip panduan:** ketika dua komponen dari program yang sama tidak sepakat soal semantik satu operasi, ketidaksepakatan itu adalah exploit-nya. *Duplicate* dan *release* milik Phantom Device tidak sepakat soal kepemilikan: duplicate membuat handle pemilik kedua, release mempercayai refcount yang tidak pernah disentuh duplicate. Audit setiap operasi yang membaca, menulis, atau mentransisi state pada objek bersama, lalu diff bagaimana tiap operasi menanganinya — Phantom Device punya tepat enam operasi yang menyentuh tabel device-handle, dan membandingkan keenamnya baris-demi-baris memunculkan asimetri duplicate/release dalam satu pass.

**Pelajaran untuk defender:** `dup()`/`duplicate_handle()` apa pun harus increment refcount objek yang direferensikannya di saat yang sama dengan menulis ke tabel descriptor — kedua operasi itu harus atomik dari sudut pandang state ownership.

## Flag

```
BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}
```
