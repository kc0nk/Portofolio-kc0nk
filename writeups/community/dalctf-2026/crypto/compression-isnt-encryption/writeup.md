---
ctf: "DalCTF 2026"
kategori: "Crypto"
challenge: "Compression isn't encryption"
flag: "dalctf{y0u_wi11_3ncrypt_4lw4y$}"
teknik: "Huffman coding yang menyamar jadi cipher; decode pertama mengacaukan bagian tengah → tiebreaker terbalik (subtree baru menang atas leaf lama)"
---

# Compression isn't encryption — DalCTF 2026 (Crypto)

## Deskripsi Singkat

Handout memberi alfabet 41 simbol (`a-z`, `0-9`, `_{}!$`) beserta frekuensinya, plus string 192-bit. Seri (tie) penting di tabel frekuensi: `{` dan `}` sama-sama `0.001`; `6`, `8`, `9` semuanya `0.02`.

Nama challenge-nya adalah seluruh diagnosisnya: **Huffman coding**, bukan cipher. Frekuensinya persis yang akan kamu berikan ke encoder Huffman.

## Analisis — Percobaan Pertama: Tiebreak Salah

Huffman `heapq` standar dengan counter menaik untuk tie-break ("item lebih lama menang") men-decode sebagian besar string dengan benar:

```
y311e8wi11_4m4eypt_32tni274
       ^^^^^^^^^^^^^^^^^^^^      bagian tengah kacau
dalctf{                          prefix benar
                          ...    suffix benar
```

Prefix dan suffix terlihat benar (karakter pembungkusnya tidak ambigu karena panjang kodenya khas), tapi bagian tengah teracak. **Itulah diagnostiknya**: ketika prefix+suffix ter-decode bersih tapi bagian tengah tidak, topologi pohonnya benar dan hanya konvensi tiebreak-nya yang terbalik.

## Eksploitasi / Solusi — Balik Arah Tiebreaker

Encoder-nya mengeluarkan **subtree hasil-merge yang baru sebelum leaf lama berprobabilitas sama** — counter tiebreaker-nya *menurun*, bukan menaik. Balik tanda counter di tuple heap, dan decoder Huffman yang sama menghasilkan:

```
dalctf{y0u_wi11_3ncrypt_4lw4y$}
```

Sketsa solusi:

```python
import heapq

freqs = parse_alphabet("alphabet.txt")
bits  = open("output (10).txt").read().strip()

heap = []
counter = 0
for ch, p in freqs.items():
    heapq.heappush(heap, (p, -counter, ch))      # negatif = yang baru menang saat seri
    counter += 1

while len(heap) > 1:
    p1, _, n1 = heapq.heappop(heap)
    p2, _, n2 = heapq.heappop(heap)
    heapq.heappush(heap, (p1 + p2, -counter, (n1, n2)))
    counter += 1

root = heap[0][2]

# telusuri bit → pohon
out = []
node = root
for b in bits:
    node = node[0] if b == '0' else node[1]
    if isinstance(node, str):
        out.append(node)
        node = root
print(''.join(out))
```

## Catatan / Insight

**Pelajaran untuk defender:** standar Huffman tidak menetapkan satu konvensi tiebreaker. Dua implementasi yang sama-sama menghasilkan kode redundansi-minimum untuk alfabet yang sama bisa berbeda byte-demi-byte kalau memecah seri secara berbeda. Di mana pun kamu melakukan interoperabilitas stream Huffman antar implementasi, tiebreak konstruksi pohon harus menjadi bagian dari spek interop. RFC 1951 (DEFLATE) menghindari masalah ini sepenuhnya dengan mentransmisikan panjang kode, bukan pohonnya.

**Kelas bug:** tiebreaker tak-terspesifikasi pada konstruksi pohon ter-serialisasi; kerapuhan interoperabilitas.

## Flag

```
dalctf{y0u_wi11_3ncrypt_4lw4y$}
```
