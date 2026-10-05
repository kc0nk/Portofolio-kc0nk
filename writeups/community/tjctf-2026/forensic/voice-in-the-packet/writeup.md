---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Forensics"
challenge: "voice-in-the-packet"
flag: "tjctf{h3y_v0ip_s73g_is_4_7hing}"
teknik: "Stego LSB pada offset genap sampel PCM G.711 µ-law RTP; 5 dari 1000 packet menyimpang dari template"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# voice-in-the-packet — TJCTF 2026 (Forensics)

## Deskripsi Singkat

Capture VoIP 20 detik dengan 1000 packet RTP audio G.711 µ-law, plus dua packet umpan berbentuk-flag.

## Analisis & Eksploitasi

Jalur yang dimaksud: **995 dari 1000 payload RTP identik byte-demi-byte**; hanya lima yang pertama menyimpang, dan hanya di offset *genap*, dengan *tepat* `0x01`. Itu stego LSB buku-teks pada sampel µ-law. XOR setiap packet non-template terhadap template-nya, kemas LSB hasilnya MSB-first, decode substring base64 di tengahnya.

## Flag

```
tjctf{h3y_v0ip_s73g_is_4_7hing}
```
