---
ctf: "BYUCTF 2026"
kategori: "Forensics"
challenge: "Are You Still There?"
flag: "byuctf{Turr3t_R3d3mpt!0n_L!n3s_4r3_N0t_R!d3s}"
teknik: "Payload ICMP echo membawa 4 byte flag masing-masing"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# Are You Still There? — BYUCTF 2026 (Forensics)

## Deskripsi Singkat

Bagian kedua dari empat challenge forensics yang berbagi pcap GLaDOS yang sama. Hint: *"bagaimana cara mengecek server online dari jarak jauh?"* → **ping**.

## Analisis

Setiap ICMP echo request membawa 4 byte flag di payload-nya.

## Eksploitasi / Solusi

```bash
$ tshark -r GLaDOS_Network.pcapng -Y 'icmp.type==8' \
        -T fields -e data.data | xxd -r -p
byuctf{Turr3t_R3d3mpt!0n_L!n3s_4r3_N0t_R!d3s}
```

"Are you still there?" adalah baris ikonik turret dari *Portal* — makanya frasa *turret redemption*.

## Catatan / Insight

**Pelajaran untuk defender:** payload ICMP tidak punya makna level-protokol di luar panjangnya. Default-allow pada ICMP echo di kebanyakan titik egress jaringan adalah alasan kenapa covert channel gaya loki/ptunnel sudah ada selama 25 tahun.

## Flag

```
byuctf{Turr3t_R3d3mpt!0n_L!n3s_4r3_N0t_R!d3s}
```
