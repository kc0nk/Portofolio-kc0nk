---
ctf: "BhAcKAri CTF 2026"
kategori: "Web"
challenge: "BhAcKAri Streaming Service"
flag: "bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}"
teknik: "JS ter-obfuskasi ROT-14 membocorkan kunci AES-256-CBC C2; whitelist shell sed dilewati dengan '?' sebagai shell glob"
sumber: "https://github.com/Abdelkad3r/bhackari-ctf-2026"
---

# BhAcKAri Streaming Service — BhAcKAri CTF 2026 (Web)

## Deskripsi Singkat

`GET http://streaming.challs.ctf.bhackari.it:8000/` mengembalikan halaman streaming anime yang langsung menjalankan script self-invoking raksasa di `<head>`. Script-nya membungkus sekumpulan properti berkunci dua-huruf dalam `defineProperty` bergaya `Proxy` yang **meng-ROT-14 setiap nilai string saat diakses**.

## Analisis

Dua komentar dan tiga key hasil decode mengupas obfuskasinya:

| Komentar / Key | Hasil Decode |
|---|---|
| `/*This is for you Arturo*/` (`index.html`) | nickname dev untuk analis |
| `/*use this abdul*/` (`player.html`) | nickname analis lain milik dev |
| `/*ip da cambiare*/` | bahasa Italia untuk "IP yang harus diganti" — mengarah ke host C2 |
| `SI` | `streaming.challs.ctf.bhackari.it:5687` (**C2 saudara di port 5687**) |
| `cf` | `/ads` |
| `pld` | `payload` |

Logika hasil deobfuskasi, end-to-end: script menyetel cookie di origin streaming lalu membuka tab baru yang mem-POST ke C2. Cookie tidak dibatasi per-port, jadi C2 menerima cookie `payload=<hex>` tanpa perubahan.

**Fungsi `Fe()` tersembunyi + kebocoran kunci AES.** Fungsi `Fe(e)` didefinisikan tapi tidak pernah dipanggil dari kode yang terlihat. Ia menelusuri argumennya terhadap alfabet custom 81-karakter (`vo`) dan mengeluarkan ASCII. Sebuah *string ekor* duduk di sebelah `//from the sysadmin to abdul` — juga ter-ROT-14 karena proxy-nya hanya merotasi *nilai* dictionary, bukan literal mentah. Memberi `Fe(rot14(trailing_string))` menjatuhkan catatan JSON kecil:

```jsonc
{
    "description": "Abdul, my friend, listen here, this is the last time
                    you forget the key, we can't afford to lose all the
                    datas we collected so far from user COOKIES",
    "algo":       "AES256",
    "key-uft-8":  "inshallah_nobody_will_steal_this",
    "IV":         "00000000000000000000000000000000",
    "Mode":       "CBC"
}
```

AES-256-CBC, IV semua-nol, padding PKCS#7, kunci `inshallah_nobody_will_steal_this`.

**C2 mengevaluasi `cmd` lewat shell yang di-whitelist.** Mendekripsi blob hex dari cookie legitim mengungkap popunder ini mencoba mengeksfiltrasi field `cmd` yang dijalankan lewat shell setelah menegakkan whitelist: `[A-Za-z]`, spasi, `-`, `?`. File `flag.txt` dikecualikan dari akses world-readable.

## Eksploitasi / Solusi

Rantai eksploitnya: enkripsi AES-256-CBC `{"cmd": "sed -n p flag?txt"}` dengan kunci bocoran + IV nol, hex-encode, setel sebagai cookie `payload=…`, POST ke `http://…:5687/`. Kenapa `sed -n p flag?txt` lolos whitelist:

- Semua karakter di `sed -n p flag?txt` adalah huruf, spasi, hyphen, atau literal `?`. ✓
- `?` adalah **shell glob** yang cocok dengan tepat satu karakter. `flag?txt` mengembang jadi `flag.txt` (tidak ada match lain di direktori kerja).
- `sed -n p <file>` mencetak isi file.

Sed membaca file sebagai `hasher` (proses C2), yang punya akses baca ke `flag.txt` — "aku blokir flag dari dunia" milik dev cuma mencabut izin *other-user*.

## Catatan / Insight

**Pelajaran untuk web:** **karakter shell glob bukan tanda baca; mereka wildcard di bawah shell apa pun yang membungkus execve.** Whitelist yang mengizinkan `?` sambil mengecualikan `.` adalah whitelist yang mengizinkan match satu-karakter apa pun terhadap nama file apa pun — termasuk file yang justru ingin dikecualikan dev. Perbaikan yang benar adalah `execve("/usr/bin/sed", argv)` langsung (tanpa shell), atau memvalidasi path file *hasil resolve* terhadap allowlist, bukan command sumbernya.

## Flag

```
bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}
```
