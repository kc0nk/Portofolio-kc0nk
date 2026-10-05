---
ctf: "Anti-Slop CTF 2026"
kategori: "Web Exploitation"
challenge: "SloppedRider"
flag: "slopped{riding_0n_M3?}"
teknik: "SSRF ke ops server loopback yang body-nya dipantulkan balik lewat field sample di respons error, membocorkan HMAC score key untuk memforge ride ticket"
---

# SloppedRider — Anti-Slop CTF 2026 (Web Exploitation)

## Deskripsi Singkat

App Node/Express yang menampilkan game balap motor di mana terrain-nya dihasilkan dari chart saham sungguhan. Flag terbuka di `TARGET_SCORE = 676767`. Skor tertinggi yang bisa dihasilkan ride legitim dibatasi `5000` — celah antara main legit dan flag sekitar 135×.

## Analisis

`SCORE_KEY` dibangkitkan sekali saat server start; kalau kamu tahu kuncinya, kamu bisa memforge ride ticket dengan `cap` berapa pun.

**Konfirmasi ticket signature sebagai gerbang.** Ticket-nya di-encode `base64url(JSON) + "." + base64url(HMAC-SHA256(payload, SCORE_KEY))`. Server memverifikasi signature-nya dengan `crypto.timingSafeEqual` (jadi serangan timing side-channel tidak akan berhasil), lalu menegakkan `score <= ticket.cap`. Tidak ada bypass cerdik di layer pengecekan skor. Satu-satunya jalan adalah memforge ticket dengan `cap` minimal `676767`, dan satu-satunya jalan memforge-nya adalah mengetahui `SCORE_KEY`.

**SSRF di endpoint preview.** `POST /api/chart/preview` membaca `url` dari body request dan mem-fetch-nya server-side dengan module `http`/`https` bawaan Node. Protokolnya dibatasi ke `http:` dan `https:`. Ada timeout 2.5 detik dan cap body 64 KB. **Tidak ada allow-list, tidak ada proteksi DNS-rebinding, tidak ada blok range loopback/private.** Yang terakhir itu petunjuknya. Kalau satu-satunya constraint adalah "harus bicara HTTP", maka servis HTTP apa pun yang bisa dijangkau container jadi target sah, termasuk `127.0.0.1`.

**Menemukan ops server internal.** Grep melalui `server.js` menjawab langsung: ada listener kedua yang di-bind hanya ke loopback. `127.0.0.1:43219/ops/config` mengembalikan `SCORE_KEY` dalam plaintext. Seluruh soal ini runtuh jadi "buat endpoint preview mem-fetch URL itu dan temukan cara membaca body-nya di respons."

**Membuat jalur error mengembalikan body-nya.** Ops server merespons objek JSON tanpa array `prices`. `normalizeChart()` menolaknya. Endpoint-nya mengembalikan error, **tapi jalur error-nya menyertakan 600 byte pertama dari body hasil fetch di field `sample`**:

```js
res.status(400).json({
  error: "chart feed must include 8-256 positive prices",
  sample: result.body.slice(0, 600)
});
```

Itulah seluruh bug-nya. Maksud pembuat kode mungkin membantu user men-debug "tunggu, chart server-ku sebenarnya mengembalikan apa?" — masuk akal untuk chart server yang dikontrol user normal. Pada URL yang dikontrol attacker menunjuk ke loopback, field `sample` jadi **oracle refleksi body**. Respons SSRF-nya menampilkan `scoreKey` langsung dalam plaintext.

## Eksploitasi / Solusi

Dengan kunci di tangan, sisanya mekanis: bangun payload JSON dengan `cap` di target, base64url-encode, HMAC-SHA256 dengan kunci itu, base64url signature-nya, gabungkan dengan `.`:

```python
import base64, hmac, json
from hashlib import sha256

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

score_key = "<scoreKey dari SSRF>"
payload = {"v": 1, "kind": "ride", "symbol": "SLOP", "cap": 999999, "iat": 0}
body = b64url(json.dumps(payload).encode())
sig = b64url(hmac.new(score_key.encode(), body.encode(), sha256).digest())
ticket = f"{body}.{sig}"
```

Submit skor ≥ `676767` dengan ticket forge ini:

```
slopped{riding_0n_M3?}
```

## Catatan / Insight

Kedua bug-nya adalah kegagalan *komposisi*. SSRF dan sistem penandatanganan ticket masing-masing baik-baik saja sendiri-sendiri; respons error yang memantulkan body hasil fetch kembali ke pemanggil adalah sambungannya (the seam). Kalau kamu mengambil satu hal dari writeup ini, ambil itu — bug yang membayar hidup di celah antar komponen.

**Pelajaran untuk defender:** field debug/diagnostik apa pun yang menyertakan konten mentah dari fetch yang dikontrol attacker adalah oracle refleksi menunggu terjadi. SSRF harus digerbangi allow-list, bukan sekadar filter skema protokol — dan proteksi loopback/private-range harus jadi default, bukan opsional.

## Flag

```
slopped{riding_0n_M3?}
```
