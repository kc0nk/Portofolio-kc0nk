---
ctf: "Anti-Slop CTF 2026"
kategori: "Reverse Engineering"
challenge: "Parallax Cartridge"
flag: "slopped{quiet_tracks_hide_in_hash_padded_resume_tapes}"
teknik: "Byte record quiet menggeser index program final cartridge runner ke bank dictionary tersembunyi yang tidak dicek audit; digabung dengan prefix MAC SHA256(secret||body) rentan SHA-256 length extension"
---

# Parallax Cartridge — Anti-Slop CTF 2026 (Reverse Engineering, 355 poin)

## Deskripsi Singkat

Dua bug bertumpuk. Pertama, cartridge runner membaca record `quiet` yang bisa menggeser index program final ke bank dictionary tersembunyi (`+32`) sementara langkah audit tidak melakukan pergeseran itu — cartridge yang sama lolos audit bersih tapi menjalankan opcode tersembunyi. Kedua, token resume BOOT-step diautentikasi dengan prefix MAC mentah `SHA256(secret || body)`, yang rentan terhadap length extension.

## Analisis

**Bagaimana serangan length-extension SHA-256 bekerja di sini.** SHA-256 adalah hash Merkle-Damgård, artinya digest akhirnya adalah state internal di akhir blok kompresi terakhir. Dengan `digest = SHA256(secret || body)` dan panjang `|secret| + |body|` diketahui, kamu bisa merekonstruksi state internal, menambahkan padding Merkle-Damgård kanonik untuk panjang pesan asli ("glue"), lalu melanjutkan kompresi dengan ekstensi pilihanmu. Digest hasilnya adalah `SHA256(secret || body || glue || extension)` yang valid walau kamu tidak pernah tahu `secret`-nya.

**Kenapa kemenangan duplicate-field penting di sini.** Body token di-encode TLV dengan record ber-tag field. Decoder state Go membaca field berurutan dan menyimpan tiap field ke map yang di-key oleh tag field. Ketika ia menemukan tag duplikat, nilai yang lebih baru diam-diam menimpa yang lebih awal. Artinya sufiks length-extension bisa men-set-ulang field yang sudah di-set body asli, termasuk cookie runner untuk program yang akan dieksekusi.

**Kamu tidak perlu memulihkan secret-nya.** Seluruh inti serangan length-extension adalah secret-nya tetap rahasia dan kamu tetap bisa memforge MAC valid. Secret server 32-byte tidak bisa dipulihkan dari satu digest legitim; yang bisa kamu lakukan, dengan satu digest legitim di tangan, adalah **memperpanjang** pesan yang diautentikasinya. Token hasil forge tidak pernah membocorkan atau membutuhkan secret-nya.

## Eksploitasi / Solusi

Alur eksploit lengkap: parse `starter.qar`, temukan `dict`, `prog`, `quiet`; mutasi `quiet[1] |= 1` untuk membelokkan runner ke bank tersembunyi; decode index program yang terlihat; ganti index terlihat terakhir `4` dengan index tersembunyi `4+32=36`; bangun byte program runner tersembunyi dengan menggabungkan `dict[i*4:(i+1)*4]` untuk tiap `i` di `[0,1,2,3,36]`; hitung cookie runner 4-byte sebagai `SHA256("parallax/runner-cookie/v5" || runner_program)[:4]`; kirim `BOOT <base64(cartridge asli)>` dan tangkap token yang dikembalikan; lakukan length-extend terhadap digest SHA-256 token, menambahkan `\xf0\x01\x01\xf0\x06<cookie>` setelah body asli, diawali padding glue Merkle-Damgård kanonik; kirim `STEP <base64(cartridge hasil mutasi)> <base64(token hasil forge)>`.

```
OK FLAG slopped{quiet_tracks_hide_in_hash_padded_resume_tapes}
```

## Catatan / Insight

Split parser audit/runtime punya bentuk yang sama dengan bug Slipstream Cache di track web: di mana pun dua consumer menelusuri buffer yang sama dengan logika decoder berbeda, kamu mendapat differential. Format cartridge sangat rentan terhadap ini karena langkah audit biasanya dimaksudkan **cepat** dan membaca subset field, sementara runner harus membaca semuanya. Defender memperbaikinya dengan men-serialize fungsi kanonikalisasi yang sama dari kedua consumer, sehingga audit dan runner menelusuri logika decoding yang identik dan hanya berbeda di gerbang "apakah ini aman?"

Kelemahan prefix-MAC lebih tua dan lebih tajam. `SHA256(secret || message)` sudah dikenal sebagai anti-pattern sejak awal 2000-an ketika serangan length-extension terhadap MD5 dan SHA-1 masuk literatur. HMAC distandardisasi tahun 1997 khusus untuk mengalahkan serangan ini. Protokol modern mana pun yang memakai prefix MAC mentah sedang mengirimkan bug berumur 25 tahun. Perbaikannya satu baris di kebanyakan bahasa: `hmac.new(secret, message, sha256).digest()` di Python, `crypto/hmac` di Go.

**Untuk defender yang mereview protokol custom apa pun dengan state yang bisa di-resume:** audit setiap urutan byte yang melintasi trust boundary. Format token? HMAC, bukan raw hash. Decoder state? Tolak field duplikat secara default, jangan diam-diam ditimpa. Pass audit vs pass runtime? Satu fungsi kanonikalisasi yang dibagi keduanya, bukan dua decoder paralel.

## Flag

```
slopped{quiet_tracks_hide_in_hash_padded_resume_tapes}
```
