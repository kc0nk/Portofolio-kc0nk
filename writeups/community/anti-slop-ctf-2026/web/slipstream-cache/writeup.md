---
ctf: "Anti-Slop CTF 2026"
kategori: "Web Exploitation"
challenge: "Slipstream Cache"
flag: "slopped{split_parsers_make_signed_packages_liable}"
teknik: "Differential parser TLV (signed_len vs manifest_len) berujung SSRF loopback, lalu blind RSA signature oracle atas raw digest tanpa padding untuk memforge sertifikat operator"
sumber: "https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/web"
---

# Slipstream Cache — Anti-Slop CTF 2026 (Web Exploitation)

## Deskripsi Singkat

Registry package custom bernama format `SPK1` yang verifier dan installer-nya tidak sepakat soal byte mana yang diautentikasi. Tidak ada endpoint listing yang terekspos, tidak ada form admin login — satu-satunya jalan adalah reverse sample package.

## Analisis

**Struktur package.** `SPK1` adalah package luar, `CRT1` adalah body sertifikat vendor. Format binary custom sepenuhnya, tanpa zip/tar/kompresi. Upload sample tanpa modifikasi mengembalikan transcript verifier yang membocorkan seluruh mental model formatnya:

```
signed_len=19 manifest_len=32
```

Dua angka ini adalah kuncinya. Verifier mengautentikasi 19 byte sementara package secara keseluruhan membawa manifest 32-byte. Siapa pun yang menulis format ini menanamkan dua panjang berbeda dan tidak merekonsiliasinya. Hipotesis kerja: verifier menandatangani 19 byte pertama dan mempercayai dirinya sendiri, installer mem-parsing seluruh 32 byte dan mempercayai verifier, dan di suatu tempat di 13 byte ekstra itu ada payload yang tidak ditandatangani dan bisa dikontrol attacker.

**Layout manifest** ter-TLV-encode: satu byte tag, dua byte panjang big-endian, lalu value. Dua TLV pertama (`name=lantern`, `cmd=static`) persis 19 byte = `signed_len`. TLV ketiga (`cache-warm`) menambah 13 byte lagi = 32 byte total (`manifest_len`), **tidak tercakup signature**. Apa pun yang ditambahkan setelah prefix yang ditandatangani ikut menumpang di atas signature RSA asli yang valid.

**Mengubah `signed_len` jadi SSRF.** Karena `manifest_len` mengontrol apa yang di-parsing installer, byte yang ditandatangani, sertifikat asli, dan signature RSA asli bisa dipertahankan sambil menambahkan TLV yang menukar command runtime. Menambahkan `cmd=fetch` plus `url=http://127.0.0.1:20024/internal/` membuat installer mem-fetch URL loopback dan mengembalikan body-nya di log instalasi — kita sekarang punya HTTP client loopback-only.

**Menemukan API internal.** `http://127.0.0.1:20024/internal/` mengembalikan daftar route maintenance: `/internal/blind-sign?role=operator&blinded=<hex>` dan `/internal/flag?cert=<b64>&sig=<b64>`. Keduanya tidak bisa dijangkau dari luar, tapi bisa dijangkau lewat package fetch hasil forge.

**Memahami signature sertifikat.** Memanggil blind signer dengan `blinded=01` mengembalikan modulus `n` dan exponent `e`. Dengan nilai itu, signature sertifikatnya terverifikasi sebagai `pow(sig, e, n) == int(SHA256(cert_body))` — CA menandatangani digest SHA-256 mentah yang diinterpretasikan sebagai integer, **tanpa padding PKCS#1, tanpa DigestInfo wrapper**. Ini menjadikan endpoint-nya oracle blind-signature buku-teks: apa pun yang bisa kamu frasakan sebagai digest ter-hash bisa ditandatangani untukmu, asal kamu meng-*blind*-kannya lebih dulu supaya oracle-nya tidak sadar apa yang baru saja diminta.

**Byte role operator.** Byte role/class sertifikat ada di offset `0x00a`. Sample-nya punya nilai `1` (public). Mengubahnya jadi `2` dan mencoba upload memberi error "only public vendor packages may be uploaded" — informasi berguna: server mengenali formatnya tapi menolak role-nya. Role `2` terlihat seperti operator, dan route flag internal secara spesifik meminta sertifikat operator.

## Eksploitasi / Solusi

Dansa blind-signature RSA kanonik: flip byte role sertifikat `1→2`, hitung `m = int(SHA256(cert_body))`, pilih `r` acak dengan `gcd(r,n)=1`, kirim `blinded = (m·r^e) mod n` ke `/internal/blind-sign`, terima `signed_blinded`, hitung `sig = signed_blinded · r^-1 mod n`. Oracle-nya melihat `m·r^e`, mengembalikan `(m·r^e)^d = m^d·r`; mengalikan dengan `r^-1` memberi `m^d` yang kita inginkan, dan oracle tidak pernah melihat `m` yang di-unblind yang baru saja ditandatanganinya.

Kirim sertifikat hasil forge ke `/internal/flag?cert=<b64>&sig=<b64>` lewat package fetch yang sama:

```
slopped{split_parsers_make_signed_packages_liable}
```

## Catatan / Insight

Tiga keputusan desain yang masing-masing masuk akal bersama-sama membentuk kemenangan: verifier dan installer ditulis oleh orang yang sepakat soal *format* tapi tidak soal *trust boundary*; CA menandatangani digest hash mentah tanpa padding (persis properti yang membuat serangan blind-signature berhasil — signature RSA dengan padding PKCS#1 v1.5 atau PSS yang benar tidak bisa di-blind dengan cara yang sama karena padding-nya bergantung pada pesan secara non-multiplikatif); dan route flag menerima sertifikat mana pun dengan role byte 2 tanpa mengecek issuer, revocation list, atau kid. Masing-masing adalah yellow flag di code review; bersama-sama mereka jadi rantai lengkap. Flag-nya sendiri mengejanya: dua parser, satu signature, dua putusan berbeda.

## Flag

```
slopped{split_parsers_make_signed_packages_liable}
```
