---
ctf: "BYUCTF 2026"
kategori: "Forensics"
challenge: "Alright. Paradox Time"
flag: "byuctf{S0_My_P4r4d0x_!d34_D!dnt_W0rk}"
teknik: "Detik-dari-baseline pada timestamp NTP mengkodekan byte ASCII, sesuai urutan field"
---

# Alright. Paradox Time — BYUCTF 2026 (Forensics)

## Deskripsi Singkat

Bagian pertama dari empat challenge forensics bertema *Portal* yang berbagi satu `GLaDOS_Network.pcapng` 49-paket yang membawa NTP, ICMP, dan HTTP. Hint-nya berbunyi *"protokol apa yang berkaitan dengan waktu?"* — **NTP**.

## Analisis

Pcap-nya punya 10 paket client NTPv4 ke UDP/13337, masing-masing membawa empat field timestamp (`reftime`, `org`, `rec`, `xmt`) semuanya dalam jendela ~2 menit tanggal `2089-12-21`. Jumlah detik-dari-baseline mengkodekan satu byte ASCII per field:

```python
secs = [hh*3600 + mm*60 + ss for ts in timestamps]
base = min(secs)
flag = bytes(s - base for s in secs).rstrip(b"\x00")
```

## Eksploitasi / Solusi

Membaca field-nya dalam urutan `reftime, org, rec, xmt` melintasi 10 paket:

```
byuctf{S0_My_P4r4d0x_!d34_D!dnt_W0rk}
```

Plaintext-nya adalah baris Wheatley: *"So my paradox idea didn't work."* (jadi ide paradoxku tidak berhasil).

## Catatan / Insight

**Pelajaran untuk defender:** protokol apa pun dengan field numerik bebas-bentuk adalah covert channel. Timestamp NTP, TTL DNS, sequence number TCP, nilai GREASE TLS — semuanya pernah dipakai di dunia nyata. Kalau IDS-mu menganggap NTP sebagai jinak, penyerang tahu itu.

## Flag

```
byuctf{S0_My_P4r4d0x_!d34_D!dnt_W0rk}
```
