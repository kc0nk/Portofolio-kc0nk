---
ctf: "NoHackNoCTF 2026 (NHNC)"
kategori: "Forensics"
challenge: "Kira-Notes"
flag: "NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}"
teknik: "Firefox places.sqlite sebagai narasi kronologis → link Proton Drive → image GPT+ext4 → carving unallocated block untuk PNG & ZIP → ZIP WZ-AES dibuka dengan pyzipper"
sumber: "https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/forensics/kira-notes"
---

# Kira-Notes — NoHackNoCTF 2026 (Forensics)

## Deskripsi Singkat

Handout-nya adalah satu file `places.sqlite`, database "places" milik Firefox. Semua yang berikut ini sepenuhnya direkonstruksi dari riwayat browsing.

## Analisis

**Langkah 1 — Baca riwayat sebagai stage direction.**

```sql
sqlite> SELECT id, url, title FROM moz_places ORDER BY id;
```

Baris-barisnya menceritakan kisah kronologis: video K-On, profil GitHub `UmmItKin` (bio "81 repositories available"), profil yang sama dimuat ulang beberapa jam kemudian ("82 repositories" setelah repo baru di-push), `UmmItKin/Kira-Notes`, jalan memutar lewat `torvalds/linux` dan `sqlmap` (umpan/red herring), halaman event CTFtime NHNC, pencarian Proton, dan:

```
https://drive.proton.me/urls/00MNVW0SHG#do4wWWpAQ0Lw
```

Fragment `#do4wWWpAQ0Lw` adalah SRP URL-password milik Proton Drive (bukan kunci dekripsi; ini bisa diketahui karena `POST /drive/urls/<token>/info` mengembalikan `Flags: 2` dan `UrlPasswordSalt`, yang merupakan rezim "link publik terproteksi password"). Riwayatnya lalu berakhir dengan kunjungan ke situs live "Retro Hacker Archive" yang semua download-nya mengembalikan 404 nginx mentah di bawah `/dl/...`, murni dekorasi.

Petunjuk yang bisa ditindaklanjuti hanya satu: URL Proton Drive.

**Langkah 2 — Kendalikan Proton lewat Playwright.** Proton Drive tidak melayani `curl` (SRP + PGP + dekripsi blok terjadi di JavaScript). Playwright headless mengklik tombol Download di setiap baris:

```python
await page.goto("https://drive.proton.me/urls/00MNVW0SHG#do4wWWpAQ0Lw",
                wait_until="networkidle", timeout=120_000)
buttons = await page.query_selector_all("button, a")
for idx in (7, 10, 13):
    async with page.expect_download(timeout=600_000) as dl_info:
        await buttons[idx].click()
    (await dl_info.value).save_as(...)
```

Tiga file mendarat: `noth_____.png` (foto sobekan kertas bertuliskan `0x0Kira` dengan ekor yang hilang), `Some Backup 01.png` (screenshot umpan), dan `of.img` (500 MB, GPT + ext4 berlabel `CASE`).

Nama file `noth_____.png` (lima underscore literal) adalah data: notenya sobek, dan lima karakter hilang.

**Langkah 3 — Iris partisi ext4.** `of.img` di-partisi GPT. Iris LBA 2048..1021951 untuk mendapatkan volume ext4:

```python
import struct
d = open("of.img", "rb").read(4096)
first, last = struct.unpack_from("<QQ", d, 1024 + 32)
# 2048, 1021951
```

Driver ext milik 7-Zip menampilkan pohon direktori live-nya:

```
home/ctf/Downloads/I
home/ctf/Downloads/will
home/ctf/Downloads/not
home/ctf/Downloads/let
home/ctf/Downloads/you
home/ctf/Downloads/see
home/ctf/Downloads/it
```

Tujuh file kosong yang mengeja `I will not let you see it`. Murni trolling. Materi sebenarnya ada di unallocated block: file yang directory entry-nya sudah dihapus tapi isinya masih ada di ruang ext4 yang tidak terpakai sampai realokasi.

**Langkah 4 — Carve signature PNG dan ZIP.** Dua file signature yang mengerjakan semuanya:

- PNG: `89 50 4E 47 0D 0A 1A 0A` ... `IEND\xaeB\x60\x82`
- ZIP local file header: `PK\x03\x04`; EOCD: `PK\x05\x06` + 22 byte

```python
import re
part = open("of_part.img", "rb").read()

png_start = re.search(rb"\x89PNG\r\n\x1a\n", part).start()
png_end   = part.find(b"IEND\xaeB\x60\x82", png_start) + 8
open("wtf.png", "wb").write(part[png_start:png_end])

idx       = part.find(b"flag.txt")
zip_start = part.rfind(b"PK\x03\x04", 0, idx)
eocd      = part.find(b"PK\x05\x06", idx)
open("final.zip", "wb").write(part[zip_start:eocd + 22])
```

Dua artefak muncul. `wtf.png` adalah note yang tidak sobek: `0x0Kira1337`. `final.zip` berukuran 255 byte dengan satu entri AES-256 (WZ-AES) `flag.txt` (55 byte).

**Langkah 5 — Buka ZIP AES-nya.** `unzip` menolak ("need PK compat. v5.1"). 7-Zip bawaan pada beberapa build melaporkan sukses tapi menulis nol byte. `pyzipper` menangani WZ-AES / AE-2 dengan benar. Huruf besar-kecil penting:

```python
import pyzipper
for pw in ("0x0Kira1337", "0x0kira1337"):
    try:
        with pyzipper.AESZipFile("final.zip") as z:
            z.setpassword(pw.encode())
            print(pw, "->", z.read("flag.txt"))
            break
    except RuntimeError as e:
        print(pw, "FAIL:", e)
```

## Eksploitasi / Solusi

```
0x0Kira1337 FAIL: Bad password for file 'flag.txt'
0x0kira1337 -> b'NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}\n'
```

## Catatan / Insight

Dua sentuhan yang bagus layak disebut. Label image disk `CASE` adalah kedipan mata untuk analis forensik; volumenya secara harfiah menamai dirinya sendiri sebagai item pekerjaan. Dan flag itu sendiri adalah pembayaran teka-tekinya: kartu challenge dengan sengaja menghilangkan kategorinya, dan membaca `n0w_y0u_kn0w_h0w_t0_f0r3ns1c` dengan lantang mengungkap kategori mana itu.

## Flag

```
NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}
```
