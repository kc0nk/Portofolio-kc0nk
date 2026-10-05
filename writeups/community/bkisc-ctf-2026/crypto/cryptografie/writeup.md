---
ctf: "BKISC CTF 2026"
kategori: "Crypto"
challenge: "Cryptografie"
flag: "plfanzen{w3Ll_D0N3,_0R_Sh0Uld_1_R4Th3R_S4Y_V2VsbCBkb29uZQ==}"
teknik: "Membalik encoding Java AltBase64 milik FileSystemPreferences yang diterapkan di atas byte UTF-16 BE"
sumber: "https://github.com/Abdelkad3r/bkisc-ctf-2026/tree/main/Cryptografie"
---

# Cryptografie — BKISC CTF 2026 (Crypto)

**Info soal:** Easy, 50 poin.

## Deskripsi Singkat

Kita diberikan satu string ciphertext. Petunjuk satu-satunya adalah nama fungsi Java: `java.util.prefs.FileSystemPreferences.dirName()`. Itu saja — seluruh soal bertumpu pada petunjuk ini.

```text
_!(!!b!"m!'%!bg"6!'`!bg"7!(c!:w":!'w!|w"%!$!!^g!z!#w!|w!w!&)!|w"^!'g!:!"_!'w!~!"f!$%!|w"]!$@!_!"o!$:!`g"f!&:!;!"~!&8!_g!y!&}!cw"i!%:!@g"r!')!:g!5!(`!{g"[!$0!>@"9
```

String ini diawali underscore, dan sisanya dibangun dari alfabet yang jelas bukan Base64 standar — mengandung `!`, `"`, `&`, `(`, `'`, backtick, kurung siku, dll.

## Recon — Apa Sebenarnya yang Dilakukan `dirName()`

`FileSystemPreferences` adalah backend berbasis disk untuk Java Preferences API di sistem mirip-Unix. Ketika sebuah node preferences punya nama yang tidak aman dipakai sebagai nama direktori, implementasinya menjalankan nama tersebut lewat helper private bernama `dirName()`, yang menambahkan underscore (`_`) di depan lalu meng-encode string sumbernya dengan skema mirip-Base64 buatan sendiri.

Alasan skema custom ini dibuat — dan alasan kenapa ini relevan di sini — adalah karena **filesystem yang case-insensitive** (macOS HFS+/APFS, Windows NTFS pada banyak konfigurasi) menganggap `Foo/` dan `foo/` sebagai direktori yang sama. Base64 standar memakai `A-Z` dan `a-z` sekaligus, jadi nama hasil encoding bisa bentrok (collision) di filesystem semacam itu. Solusi JDK adalah **alfabet custom 64-simbol yang sama sekali tidak mengandung huruf kapital** — kadang disebut *Java AltBase64*. Dari membaca [`FileSystemPreferences.java` di OpenJDK](https://github.com/openjdk/jdk/blob/master/src/java.prefs/unix/classes/java/util/prefs/FileSystemPreferences.java), alfabetnya adalah:

```text
!"#$%&'(),-.:;<>@[]^`_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?
```

64 simbol, masing-masing dipetakan ke nilai 6-bit `0..63` sesuai urutan tersebut. Melihat ciphertext-nya — `_`, lalu `!`, `(`, `b`, `m`, `'`, dst. — setiap karakternya memang berasal dari alfabet ini.

Ada satu keanehan lagi yang spesifik-JDK yang perlu diketahui: **`FileSystemPreferences` bekerja pada data `String` milik Java, yang secara internal berbentuk UTF-16.** Ketika `dirName()` mengubah nama menjadi byte untuk diberikan ke encoder-nya, ia memakai representasi **UTF-16 big-endian**, bukan UTF-8. Jadi byte yang kita dapatkan dari AltBase64 **bukan** flag-nya secara langsung — itu adalah encoding UTF-16 BE dari flag.

## Eksploitasi / Solusi

Decoder-nya sekarang tinggal mekanis saja:

1. Buang underscore (`_`) di depan (penanda yang selalu ditambahkan `dirName()`).
2. Decode sisanya sebagai AltBase64 memakai alfabet di atas — tiap karakter memberi 6 bit, digabung, lalu dikelompokkan ulang jadi byte.
3. Decode byte hasilnya sebagai UTF-16 BE.

```python
ALPHABET = "!\"#$%&'(),-.:;<>@[]^`_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?"

def altb64_decode(s: str) -> bytes:
    bits = "".join(format(ALPHABET.index(ch), "06b") for ch in s)
    bits = bits[: len(bits) - (len(bits) % 8)]   # buang sisa sub-byte
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

ct = open("challenge.txt").read().strip()
assert ct.startswith("_")
print(altb64_decode(ct[1:]).decode("utf-16-be"))
```

```
$ python3 solve.py
plfanzen{w3Ll_D0N3,_0R_Sh0Uld_1_R4Th3R_S4Y_V2VsbCBkb29uZQ==}
```

## Catatan / Insight — Lelucon Berlapis

Pembungkus flag-nya adalah `plfanzen{...}`, bukan bahasa Jerman yang benar `pflanzen{...}` ("tumbuhan"). Huruf `l`/`f` yang tertukar adalah bagian dari lelucon typo berulang di CTF ini — bahkan kategori crypto-nya sendiri di UI platform diberi label "cyrpto" (typo yang sama).

Men-decode blob dalamnya, `V2VsbCBkb29uZQ==`, sebagai Base64 standar menghasilkan string ASCII `Well doone` — lelucon yang sama, huruf ganda. Sentuhan yang lucu.

**Pelajaran untuk soal serupa di masa depan:** Ketika soal crypto mengarahkanmu ke sebuah class atau fungsi spesifik dari library dunia nyata, **baca source code fungsi itu**, jangan Wikipedia. OpenJDK, .NET reference source, Go standard library, OpenSSL, Bouncy Castle — semuanya mengandung puluhan encoder sekali-pakai, skema name-mangling, dan helper serialization yang sering muncul di CTF justru karena cukup obscure untuk dijadikan teka-teki. Petunjuknya sudah memberitahu ke mana harus mencari.

**Pelajaran lainnya:**

1. **Alfabet custom adalah sebuah fingerprint.** Kapan pun kamu melihat set 64-karakter yang bukan Base64 standar, pertanyaannya adalah "alfabet library mana ini?" — dan jawabannya biasanya bisa ditemukan lewat pencarian Google atas beberapa simbol yang tidak biasa. Kehadiran `!`, `"`, dan `(` bersanding dengan huruf kecil itu *sangat* tidak lazim.
2. **Underscore di awal blob hasil encoding sering membawa makna.** `FileSystemPreferences.dirName()` memakai `_` sebagai penanda "ini sudah saya encode"; encoding atribut LDAP memakai prefix untuk atribut bernama-OID; beberapa skema berawalan `:`/`@` melakukan hal serupa. Selalu cek apakah karakter di depan itu bagian dari payload atau sekadar wrapper.
3. **UTF-16 vs UTF-8 adalah jebakan yang sering muncul saat me-reverse payload berasal-Java/Windows.** Kedua platform memakai UTF-16 secara internal; ketika API mereka men-serialize "sebuah string" menjadi byte, hampir selalu memilih UTF-16 (BE di JVM, LE di Windows). Kalau hasil decode Base64 menghasilkan byte yang mirip teks tapi banyak diselingi `\x00` di antara karakter ASCII, itu tandanya kamu sedang melihat UTF-16.

## Flag

```
plfanzen{w3Ll_D0N3,_0R_Sh0Uld_1_R4Th3R_S4Y_V2VsbCBkb29uZQ==}
```
