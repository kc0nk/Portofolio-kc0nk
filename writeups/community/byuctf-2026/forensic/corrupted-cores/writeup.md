---
ctf: "BYUCTF 2026"
kategori: "Forensics"
challenge: "Corrupted Cores"
flag: "byuctf{Th3_P4rt_Wh3r3_H3_K!lls_Y0u}"
teknik: "Source IP yang di-spoof adalah ASCII printable yang di-base64; digabung berurutan lintas semua echo"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# Corrupted Cores — BYUCTF 2026 (Forensics)

## Deskripsi Singkat

Bagian ketiga dari empat challenge forensics yang berbagi pcap GLaDOS yang sama. Dua hint: *"suara-suaranya mungkin bukan milik satu identitas"* + *"paket ARP bukan bagian dari challenge ini."* Itu menunjuk ke *pengirim* paket IP-nya — dan semua echo ICMP datang dari IP yang di-spoof berbeda-beda.

## Analisis

```text
89.110.108.49   → "Ynl1"
89.51.82.109    → "Y3Rm"
101.49.82.111   → "e1Ro"
77.49.57.81     → "M19Q"
…
100.88.48.65    → "dX0A"
```

Setiap oktet adalah byte ASCII yang bisa dicetak. Gabungkan dalam urutan echo dan decode base64.

## Eksploitasi / Solusi

```text
Ynl1Y3Rme1RoM19QNHJ0X1doM3IzX0gzX0shbGxzX1kwdX0A
  → byuctf{Th3_P4rt_Wh3r3_H3_K!lls_Y0u}
```

*"The part where he kills you"* adalah boss fight Wheatley — momen saat corrupted core benar-benar penting.

## Catatan / Insight

**Pelajaran untuk defender:** kalau kamu memasang alert untuk ICMP source-spoofed, pasang alert juga untuk *isi* dari source address-nya. Rangkaian panjang oktet ASCII-printable di `ip.src` bukan hal acak dan bukan hal jinak.

## Flag

```
byuctf{Th3_P4rt_Wh3r3_H3_K!lls_Y0u}
```
