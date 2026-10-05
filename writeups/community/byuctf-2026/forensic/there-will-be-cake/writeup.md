---
ctf: "BYUCTF 2026"
kategori: "Forensics"
challenge: "There Will Be Cake"
flag: "byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}"
teknik: "Header HTTP Cookie: cake=<base64> → decode base64"
---

# There Will Be Cake — BYUCTF 2026 (Forensics)

## Deskripsi Singkat

Bagian terakhir dari empat challenge forensics yang berbagi pcap GLaDOS yang sama. Hint: *"kue panggang yang mirip cake dan bisa ditemukan di hampir semua website."* → **HTTP cookies**. Satu request HTTP di dalam pcap, satu nilai cookie.

## Analisis

```python
>>> base64.b64decode("Ynl1Y3Rme1RoM19DNGszXyFzXzRfTCEzX0hUQzU2emVFfQ==").decode()
'byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}'
```

## Eksploitasi / Solusi

```
byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}
```

*"The cake is a lie."* (kuenya cuma bohong)

## Catatan / Insight

**Pelajaran untuk defender:** cookie HTTP adalah covert channel paling orisinal. Periksa nilai cookie untuk pola base64/hex/uuencode saat men-triase traffic yang mencurigakan sebagai beaconing.

## Flag

```
byuctf{Th3_C4k3_!s_4_L!3_HTC56zeE}
```
