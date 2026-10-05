---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Reverse"
challenge: "rotated"
flag: "tjctf{b45h_d3bu6_m4573r}"
teknik: "Empat layer bertumpuk: byte rotation → UPX → bash terobfuskasi → base64+gzip; flag ada di komentar source script"
---

# rotated — TJCTF 2026 (Reverse)

## Deskripsi Singkat

Empat layer bersarang, masing-masing murah untuk dikupas.

## Analisis & Eksploitasi

1. **Byte rotation**: setiap byte ditambah 29. Balikkan dengan `(b - 0x1d) % 256`. Hasilnya: ELF yang di-pack UPX yang valid.
2. **UPX**: `upx -d rotated-stage2`. Hasilnya: ELF yang men-drop dan mengeksekusi script bash.
3. **Bash terobfuskasi**: ~300 baris concatenation variabel berpadding `${IFS}`. Bermuara pada `eval "$(printf '<base64>' | base64 -d | gunzip -c)"`.
4. **Shell hasil decode**: mencetak sebuah banner. Flag-nya di-base64-encode di dalam sebuah komentar di *source script*, bukan di output runtime.

## Flag

```
tjctf{b45h_d3bu6_m4573r}
```
