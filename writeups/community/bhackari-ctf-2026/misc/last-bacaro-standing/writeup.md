---
ctf: "BhAcKAri CTF 2026"
kategori: "Misc"
challenge: "Last Bacaro Standing"
flag: "bhackariCTF{m4k3_b4cAr1_gr3at_4ga1n}"
teknik: "Stego LSB berkunci-seed dengan urutan shuffle random.seed; seed adalah nama bacaro (aciugheta) yang tertulis di kanopi foto carrier"
sumber: "https://github.com/Abdelkad3r/bhackari-ctf-2026"
---

# Last Bacaro Standing — BhAcKAri CTF 2026 (Misc)

## Deskripsi Singkat

Brief-nya, dalam dialek Venesia, adalah surat cinta untuk *bacari* — tavern anggur-dan-cicchetti tua khas Venesia yang makin tersingkir turis:

> *"el messagio no se vedi, ma xe dentro nei colori..."* — pesannya tidak terlihat, tapi ada di dalam warna
>
> *"el seme che serve a 'sta magia… l'è proprio el nome del posto."* — seed yang dibutuhkan sihir ini adalah nama tempat itu sendiri

Handout membawa `bacaro.png` (carrier stego), `enfilator.py` (encoder, berfungsi penuh), dan `ciapator.py` (decoder, sengaja jadi stub).

## Analisis

**Encoder-nya:**

```python
def infila_el_benedeto(quadro, messagio, dove_sbatto, semente):
    tela = Image.open(quadro).convert('RGB')
    pixels = list(tela.getdata())

    binari = ''.join(format(ord(l), '08b') for l in messagio) + '1111111111111110'

    posizioni = list(range(len(pixels) * 3))
    random.seed(semente)
    random.shuffle(posizioni)                          # ← permutasi berkunci-seed

    flat = [c for px in pixels for c in px]            # [R,G,B,R,G,B,…]
    for i, pos in enumerate(posizioni):
        if i >= len(binari): break
        flat[pos] = (flat[pos] & ~1) | int(binari[i])  # patch LSB
```

Tiga fakta yang dibutuhkan decoder: carrier dikonversi ke **RGB** sebelum dibaca; array flat adalah **R, G, B ter-interleave** row-major — setiap channel adalah kandidat carrier, bukan cuma blue; bit ditulis **dalam urutan shuffle**, bukan urutan scan (pembacaan naif "baca semua LSB kiri-ke-kanan" menghasilkan 4.6 KB sampah); terminator-nya **`0xFFFE`** (16 bit) — tidak pernah dihasilkan cuma dari batas payload ASCII.

**Mengidentifikasi seed-nya.** Buka `bacaro.png`. Kanopi merah marun membawa nama bar-nya dalam huruf putih besar: **ACIUGHETA**. La Cantina Aciugheta adalah bacaro bersejarah sungguhan dekat Campo SS. Filippo e Giacomo, beberapa menit dari Piazza San Marco. Ini cocok dengan baris brief *"el più vecio… el più duro a morir"* ("yang tertua, yang paling sulit mati").

`random.seed` milik Python meng-hash byte dari input string, jadi huruf besar-kecil penting. Mencoba beberapa varian, `aciugheta` (huruf kecil semua) yang cocok.

## Eksploitasi / Solusi

Ulangi shuffle-nya, baca LSB dalam urutan shuffle, kemas ulang bit jadi byte, berhenti di terminator `0xFFFE`:

```
bhackariCTF{m4k3_b4cAr1_gr3at_4ga1n}
```

## Catatan / Insight

**Pelajaran untuk defender:** **stego LSB dengan shuffle berkunci-seed bisa di-brute-force kalau seed-nya hidup di dalam cover-nya.** Challenge ini jujur soal itu — brief-nya memberi tahu seed-nya adalah *"il nome del posto."* Di setting adversarial, attacker akan menelusuri setiap label, tanda, field EXIF, watermark, dan string metadata yang terlihat lewat `random.seed`. Pelajaran defensifnya: kalau kamu terpaksa mengirimkan steganografi, seed-nya harus berasal dari sesuatu yang tidak bisa diamati attacker (KDF dari passphrase yang diketik user). Kalau tidak, itu cuma puzzle anak-anak.

## Flag

```
bhackariCTF{m4k3_b4cAr1_gr3at_4ga1n}
```
