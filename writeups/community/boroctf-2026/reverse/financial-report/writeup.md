---
ctf: "boroCTF 2026"
kategori: "Reverse Engineering"
challenge: "financial_report"
flag: "boroCTF{0n1_F!le_I5_@11_it_tAke$}"
teknik: "PDF 1 KB dengan object stream berisi JavaScript OpenAction; flag base64 diselipkan di antara operasi aritmetika yang sengaja tidak berguna (decoy)"
sumber: "https://github.com/Abdelkad3r/boroCTF-2026"
---

# financial_report — boroCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Sebuah file PDF berukuran 1080 byte. Namanya "laporan keuangan" (financial report), tapi ukurannya cuma 1 KB. Ketidakcocokan ini adalah sinyal pertama bahwa artefaknya menyesatkan "bungkus" (nama/label) soal.

## Recon

PDF sekecil ini biasanya memakai satu `/ObjStm` (object stream) yang menampung beberapa sub-objek sekaligus. Ekstrak isinya:

```python
import zlib
data = open('financial_report', 'rb').read()
raw  = data[data.find(b'stream\n') + 7 : data.find(b'endstream')].rstrip()
text = zlib.decompress(raw).decode('latin-1')
print(text)
```

Tool alternatif yang setara: `qpdf --qdf in.pdf out.pdf`, `mutool clean -d`, `pdf-parser.py -f`. Semuanya menghasilkan object stream yang sudah didekompresi.

## Analisis

Ada dua objek yang menarik: sebuah `/OpenAction` di catalog yang terhubung ke blob JavaScript yang jalan otomatis saat dokumen dibuka, ditambah sebuah widget annotation yang dirender sebagai tombol "Click me for free flag!" (klik untuk flag gratis).

JavaScript-nya:

```js
var a = 7;
var b = 13;
var c = a * b;
var d = c - a;
var e = [a, b, c, d];
// ... lebih banyak aritmetika umpan (decoy) ...
var encoded = "Ym9yb0NURnswbjFfRiFsZV9JNV9AMTFfaXRfdEFrZSR9";
var decoded = util.printd("yyyy", new Date());
```

Semua aritmetika di atas adalah kode mati (dead code) — tidak ada yang membaca variabel `e` atau `decoded`. Literal `encoded` adalah seluruh payload sebenarnya. Widget annotation adalah umpan: mengklik tombolnya di Adobe Reader hanya memicu `app.alert("Ya, I'm not making it that easy.")` dan tidak mencetak apa pun lagi.

## Eksploitasi / Solusi

Cukup decode base64 dari literal `encoded`:

```python
import base64
base64.b64decode('Ym9yb0NURnswbjFfRiFsZV9JNV9AMTFfaXRfdEFrZSR9').decode()
# boroCTF{0n1_F!le_I5_@11_it_tAke$}
```

## Catatan / Insight

Lelucon di dalam flag: "one file is all it takes" (satu file saja sudah cukup) cocok dengan fakta bahwa PDF 1 KB ini "mengaku" sebagai laporan keuangan yang lengkap. Semua aritmetika dan tombol interaktif hanyalah pengalih perhatian — nilai satu-satunya yang relevan adalah string base64 yang diam-diam disisipkan di tengah kode JavaScript yang kelihatannya sibuk menghitung sesuatu.

## Flag

```
boroCTF{0n1_F!le_I5_@11_it_tAke$}
```
