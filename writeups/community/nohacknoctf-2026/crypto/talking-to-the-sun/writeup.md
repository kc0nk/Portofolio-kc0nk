---
ctf: "NoHackNoCTF 2026 (NHNC)"
kategori: "Crypto (berbentuk Web)"
challenge: "Talking to the Sun"
flag: "NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}"
teknik: "ECDSA nonce same-prefix (Hidden Number Problem) diaktifkan lewat bug ekspansi panjang .lower() Python pada huruf Turki İ (U+0130); dipecahkan dengan lattice Boneh-Venkatesan/LLL"
sumber: "https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/crypto/talking-to-the-sun"
---

# Talking to the Sun — NoHackNoCTF 2026 (Crypto / Web)

## Deskripsi Singkat

Sebuah aplikasi Flask menandatangani kalimat personal dengan ECDSA di atas kurva brainpoolP512r1. Nonce-nya adalah `SHA384(nonce_salt || account) · 2^128 + urandom(16)`, jadi 384 bit teratas adalah *prefix tetap per akun*: setup klasik untuk Hidden Number Problem. Setiap akun hanya menandatangani sekali, jadi kita butuh beberapa registrasi yang resolve ke akun yang sama saat penandatanganan. Collision itu diatur lewat bug ekspansi panjang `.lower()` Python pada huruf Turki `İ`.

## Analisis

**Langkah 1 — Kenali setup HNP same-prefix.** Konstruksi nonce dari `app.py`:

```python
def nonce_for_account(account: str) -> int:
    prefix = hashlib.sha384(NONCE_SALT + account.encode("utf-8")).digest()
    while True:
        raw = prefix + os.urandom(16)
        value = int.from_bytes(raw, "big") % ORDER
        if value:
            return value
```

`k = P · 2^128 + t` dengan `P = SHA384(salt || account)` (tetap untuk akun tertentu) dan `t = urandom(16)` (128 bit segar per tanda tangan). Selisihkan dua tanda tangan dari akun yang sama:

```
k_i - k_0 ≡ t_i - t_0 (mod n),   |t_i - t_0| < 2^129
```

Itu adalah Boneh-Venkatesan HNP dengan residual kecil. Enam tanda tangan pada kurva 512-bit adalah headroom yang nyaman untuk LLL.

**Langkah 2 — Temukan batas panjang yang tidak cocok.**

```python
MAX_ACCOUNT_CHARS   = 0x9999    # 39321
STORED_ACCOUNT_CHARS = 0x10000  # 65536

def check_account(value: str) -> tuple[bool, str]:
    account = (value or "").strip()
    if not account or len(account) >= MAX_ACCOUNT_CHARS:
        return False, ""
    if ACCOUNT_RE.fullmatch(account) is None:
        return False, ""
    return True, account.lower()

def stored_account(account: str) -> str:
    return account[:STORED_ACCOUNT_CHARS]
```

Dua konstanta bersebelahan, `0x9999` dan `0x10000`, dengan `.lower()` terselip di antaranya. Untuk input ASCII, kedua batas ini konsisten (tidak ada yang lolos `< 39321` yang perlu dipotong di `65536`). Tapi `check_account` mengembalikan `account.lower()`, dan kalau `.lower()` bisa membuat string jadi lebih panjang dari dirinya sendiri, kedua batas ini menyimpang.

**Langkah 3 — Pivot lewat `İ` Turki.** `.lower()` Unicode milik Python memakai tabel case-folding lengkap. U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) menjadi huruf kecil sebagai *dua* code point: `i` (U+0069) diikuti U+0307 (COMBINING DOT ABOVE):

```
>>> "İ".lower()
'i̇'
>>> len("İ".lower())
2
```

Akun dengan 33.000 `İ` menjadi 66.000 code point setelah lowercase. Tambahkan sufiks pendek dan aritmetikanya pas:

```
email = "a@" + "İ" * 33000 + ".abcdef"
len(email)     = 2 + 33000 + 7 = 33009    < 39321   ✓ lolos check_account
len(lower)     = 2 + 66000 + 7 = 66009    > 65536   → terpotong saat disimpan
```

Dua email yang hanya berbeda di 6 karakter akhir punya (a) `stored_account` yang identik (posisi 65536 jatuh di dalam rangkaian `i̇` yang identik) dan (b) `account_fingerprint` yang berbeda (SHA-256 dari seluruh string yang sudah di-lowercase, yang melihat bagian ekornya). Jadi keduanya terdaftar sebagai user berbeda tapi menandatangani dengan prefix nonce yang sama.

**Langkah 4 — Kumpulkan enam tanda tangan dengan prefix sama.** Enam akun berbentuk `a@ + İ×33000 + .<random6>`. Untuk masing-masing: register → login → `/api/generate` mengembalikan token `singen.<b64payload>.<b64sig>`. Decode jadi `(account, message, r, s)`. Keenam token harus membawa field `account` yang *identik* di payload-nya (bukti collision-nya berhasil); kalau tidak, LLL tidak akan konvergen.

**Langkah 5 — Jalankan LLL.** Misalkan `a_i = s_i^-1 r_i` dan `c_i = s_i^-1 z_i` (dengan `z_i = SHA512(canonical(account, message_i))`). ECDSA memberi `k_i = a_i · d + c_i (mod n)`. Selisihkan terhadap sig 0:

```
(a_i - a_0) · d + (c_i - c_0) ≡ (t_i - t_0)  (mod n),   |t_i - t_0| < 2^129
```

Bangun lattice Boneh-Venkatesan standar dengan faktor skala `s = 2^383` (menyeimbangkan norma target-vector terhadap ukuran alami `d` yang ~2^512), reduksi dengan `fpylll`, telusuri basis hasil reduksi untuk baris yang M entri pertamanya kecil dan slot konstannya `±2^512`. Koordinat ke-M dari baris itu adalah `±d`.

```
[*] target: http://nhnc2.whale-tw.com:10022   collecting 6 same-prefix signatures
[+] sig 6/6 in 5.8s
[*] all 6 tokens share the stored account (len=65536 code points) → same nonce prefix
[*] running LLL on 6-sig lattice
[+] recovered d bits = 511
```

## Eksploitasi / Solusi

Dengan `d` di tangan, tanda tangani token baru dengan `account = "whale@whale-tw.com"` (string admin yang dicek `verify_token`) dan `message` apa pun (cabang flag tidak membandingkan message):

```python
account = "whale@whale-tw.com"
message = "sing"
z = int.from_bytes(hashlib.sha512(canonical(account, message).encode()).digest(), "big")
k = random.randrange(1, n)
r = (k * G).x() % n
s = (inverse_mod(k, n) * (z + r * d)) % n
sig = r.to_bytes(64, "big") + s.to_bytes(64, "big")
token = f"singen.{b64u(canonical(account, message).encode())}.{b64u(sig)}"
```

`POST /api/verify` mengembalikan:

```json
{"flag":"NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}","message":"sing","ok":true}
```

## Catatan / Insight

Pelajarannya duduk di tiga tempat sekaligus: `str.lower()` tidak melestarikan panjang di Unicode (`İ`, `ß`, dan segelintir lainnya); kode apa pun yang memvalidasi panjang sebelum normalisasi tapi menyimpan/membatasi setelah normalisasi punya bug keterkaitan-truncation; dan prefix hasil hash bukanlah nonce, karena determinisme di bit-bit teratas meruntuhkan ECDSA jadi HNP begitu penyerang mendapat amplifikasi tanda tangan di bawah identitas yang sama. Nonce deterministik RFC 6979 menutup seluruh kelas ini.

## Flag

```
NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}
```
