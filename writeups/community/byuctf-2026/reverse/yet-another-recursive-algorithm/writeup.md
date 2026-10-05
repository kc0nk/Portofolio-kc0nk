---
ctf: "BYUCTF 2026"
kategori: "Reverse Engineering"
challenge: "Yet Another Recursive Algorithm"
flag: "byuctf{why_do3s_yara_st4nd_f0r_th4t???}"
teknik: "Constraint condition milik rule YARA (byte literal + assert integer-at-offset) dipakai sebagai constraint solver mundur"
---

# Yet Another Recursive Algorithm — BYUCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Handout-nya adalah satu rule YARA. `condition`-nya adalah `all of them and uint32(21)==0x6E347473 and uint16(28)==0x7230 and uint16be(29)==0x725F`. Tujuh belas string `$a..$q` dan tiga assert integer-at-offset bersama-sama membatasi sebuah plaintext 39-byte.

## Analisis

- `$c = /byuctf.{33}/` ⇒ panjang = **6 + 33 = 39**.
- `$j = /\?{3}\}/` ⇒ berakhir dengan **`???}`**.
- `uint32(21) == 0x6E347473` (LE) ⇒ `flag[21..25] = "st4n"`.
- `uint16(28) == 0x7230` (LE) ⇒ `flag[28..30] = "0r"`.
- `uint16be(29) == 0x725F` (BE) ⇒ `flag[29..31] = "r_"`.

Setiap string hex-dengan-wildcard (`{ 77 ?8 79 }`) dan string berhias-XOR (`"EY\x05E\x0e" xor` dengan kunci `0x31`) menetapkan 2–4 byte lagi. Menggabungkan semua constraint ini secara unik mengidentifikasi flag-nya.

## Eksploitasi / Solusi

```
byuctf{why_do3s_yara_st4nd_f0r_th4t???}
```

`YARA` = *"Yet Another Recursive Acronym"* — makanya judulnya.

## Catatan / Insight

**Pelajaran untuk defender:** keyword `condition` milik YARA adalah bahasa ekspresi kecil. Sebagai tool *maju*, ia mencocokkan malware. Dipakai sebagai constraint solver *mundur*, ia menspesifikasikan sebuah plaintext. Siapa pun yang membaca rule YARA untuk mata pencahariannya bisa menulisnya sebagai challenge.

## Flag

```
byuctf{why_do3s_yara_st4nd_f0r_th4t???}
```
