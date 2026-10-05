---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Forensics"
challenge: "loud-packets"
flag: "tjctf{v3ry_l0ud_pc4p_f1le}"
teknik: "Bukan PCAP sama sekali — image raksasa yang tiap tile-nya adalah versi downscale sprite anime, rendering bitmap-font dari flag"
---

# loud-packets — TJCTF 2026 (Forensics)

## Deskripsi Singkat

Namanya adalah pengalih perhatian — tidak ada PCAP sama sekali. Challenge-nya berisi direktori 39 folder (satu per simbol charset flag TJCTF) sprite anime yang identik, plus `chall.png` grayscale besar (3664×784) penuh blob berbentuk-dumbbell putih.

## Analisis & Eksploitasi

Triknya: blob-blob itu adalah versi downscale dari sprite anime-nya, dan **gambar puzzle-nya adalah rendering bitmap-font dari flag**, dengan setiap karakter digambar sebagai tile kira-kira 80×80 dari sprite yang bersesuaian. Downsample gambar itu dengan nearest-neighbour jadi satu pixel per tile, threshold di 128, cetak `#` atau spasi, baca ASCII art-nya.

```python
small = im.resize((im.width // 80, im.height // 80), Image.NEAREST)
for y in range(small.height):
    print("".join("#" if small.getpixel((x, y)) > 128 else " " for x in range(small.width)))
```

## Flag

```
tjctf{v3ry_l0ud_pc4p_f1le}
```
