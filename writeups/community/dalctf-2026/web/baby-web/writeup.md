---
ctf: "DalCTF 2026"
kategori: "Web Exploitation"
challenge: "Baby Web"
flag: "dalctf{n0w_y0u_ar3_th3_b0ss_b4by}"
teknik: "Atribut HTML hidden=\"true\" menyembunyikan flag dari render browser, tapi byte-nya ada di source"
---

# Baby Web — DalCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Satu halaman HTML statis ~52 KB bergaya ringkasan film dan transkrip *Boss Baby*. Tanpa script, tanpa form, tanpa endpoint lain — tidak ada yang bisa di-fuzz, tidak ada attack surface.

Sebuah `<h2>` di dekat bagian bawah memberi petunjuk:

> the flag is somewhere in the transcript

Flag-nya dibungkus tag `<p hidden="true">…dalctf{…}…</p>`. Atribut HTML `hidden` menekan *rendering* di browser, tapi byte-nya tetap ada di source.

## Eksploitasi / Solusi

Pakai *View Source* di browser, atau:

```
curl -s https://<instance>.instancer.dalctf2026.com/ | grep -E 'hidden=|dalctf\{'
```

Hasilnya:

```
dalctf{n0w_y0u_ar3_th3_b0ss_b4by}
```

## Catatan / Insight

Poin belajarnya lebih luas dari sekadar trik atribut `hidden`: ketika halaman tidak merender sesuatu yang berguna, source-nya bukan halamannya. Daftar periksa satu-langkah "benarkah tidak ada di sana?" untuk challenge web apa pun:

- `<element hidden>` dan `<element hidden="true">` (atribut HTML)
- CSS `display: none`, `visibility: hidden`, `opacity: 0`
- Teks putih-di-atas-putih (`color: white` di atas `background: white`)
- Komentar HTML `<!-- … -->`
- Tag dengan `aria-hidden="true"` (tersembunyi dari aksesibilitas, konten tetap ada)
- Posisi di luar layar (`position: absolute; left: -9999px`)
- Input form tersembunyi (`<input type="hidden">`)

`View Source` (atau `curl | grep`) menjangkau semuanya dalam satu langkah.

**Kelas bug:** batas konten-vs-render; atribut `hidden` sebagai tempat persembunyian flag.

## Flag

```
dalctf{n0w_y0u_ar3_th3_b0ss_b4by}
```
