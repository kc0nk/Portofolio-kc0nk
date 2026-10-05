# Live CTFtime Stats

Website ini sekarang mendukung pengambilan statistik CTFtime secara live melalui Cloudflare Pages Functions.

## Endpoint

Function tersedia di:

```text
/api/ctftime
```

Function mengambil:

- World Rank
- Country Rank Indonesia
- Rating Points
- Events

Sumber:

```text
https://ctftime.org/api/v1/teams/434825/
https://ctftime.org/stats/2026/ID
```

## Deploy

Deploy repository ini sebagai **Cloudflare Pages project**. Folder `functions/` akan otomatis dipakai sebagai Pages Functions.

Setelah deploy, buka:

```text
https://DOMAIN-KAMU/api/ctftime
```

Responsenya berbentuk JSON.

## Cache

Endpoint menggunakan cache selama 5 menit. Jadi pengunjung mendapatkan data yang sangat baru tanpa membuat request ke CTFtime pada setiap request.

## Static hosting

Kalau website dijalankan dengan GitHub Pages atau `python -m http.server`, Pages Function tidak tersedia. Website otomatis fallback ke `ctftime.json`.

Untuk mode live, hosting harus menyediakan backend/function seperti Cloudflare Pages Functions.
