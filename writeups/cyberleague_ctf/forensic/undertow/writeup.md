# Undertow

> **Kategori:** Forensics / Network Forensics  
> **Flag:** `CYBERLEAGUE{d3c0rr3l4t3d_curr3nts_fl0w}`

---

## 1. Deskripsi Challenge

Perimeter monitoring menyimpan sebuah capture jaringan yang berjalan cukup lama pada segmen LAN perusahaan. Secara sekilas lalu lintas yang terlihat masih tampak normal: ICMP ping, DNS lookup, dan HTTP request menuju host-host yang biasa digunakan.

Namun, SOC mencurigai adanya informasi yang diam-diam dikeluarkan (*exfiltrated*) melalui lalu lintas tersebut. Tugas kita adalah menemukan anomali, menentukan bagaimana data tersembunyi dikirim, kemudian merekonstruksi seluruh pesan sampai mendapatkan flag.

### Challenge Description

```text
Perimeter monitoring kept an unusually long capture running on a corporate LAN segment overnight. Nothing in the traffic mix looks overtly wrong on its own — the usual pings, name lookups and web requests, all to destinations the network talks to every day. The SOC is still convinced something was quietly walked out through that noise, and they can't pin down where. Here's the raw capture: find what left, and reconstruct what it was carrying.
```

### Target

Tidak terdapat server/network service yang perlu dieksploitasi. Artefak utama adalah file capture:

```text
undertow.pcap
```

### Format Flag

```text
CYBERLEAGUE{...}
```

---

# 2. Ringkasan Solving

Challenge ini menggunakan teknik **multi-channel covert exfiltration**. Pesan yang sama tidak dikirim melalui satu protokol, tetapi dipecah menjadi **39 fragmen** dan disebarkan ke tiga channel berbeda:

- **ICMP** → indeks `0–12`
- **DNS** → indeks `13–25`
- **HTTP** → indeks `26–38`

Masing-masing fragmen membawa:

```text
[index] + [character]
```

Urutan paket jaringan tidak boleh langsung dianggap sebagai urutan pesan karena pengiriman dibuat sedemikian rupa agar setiap channel terlihat normal bila dianalisis secara terpisah.

Setelah semua fragmen diekstrak, data diurutkan berdasarkan indeks global `0..38`.

Hasil akhirnya:

```text
CYBERLEAGUE{d3c0rr3l4t3d_curr3nts_fl0w}
```

---

# 3. Analisis Artefak

## 3.1 Identifikasi Subkategori

Subkategori yang paling sesuai adalah:

```text
Network Forensics
        ↓
Covert Channel Analysis
        ↓
Multi-Channel Data Exfiltration
```

Tidak terdapat indikasi utama bahwa challenge ini bergantung pada memory forensics, file carving, metadata gambar, atau steganography pada file biasa.

Fokus investigasi berada pada **isi payload jaringan**.

---

## 3.2 Gambaran Capture

Capture berisi sekitar **3.280 paket** selama kurang lebih **15 menit**.

Komposisi trafik secara umum:

| Protokol | Perkiraan Paket | Catatan |
|---|---:|---|
| ICMP | 536 | Mayoritas ping normal |
| DNS | 836 | Mayoritas query/response umum |
| HTTP/TCP | ±1.900 | Banyak request normal dan decoy |

Tidak ada kejanggalan mencolok pada field header seperti:

- TTL
- TOS
- TCP window
- IP options
- ukuran header

Artinya, pendekatan yang efektif bukan mencari paket yang "rusak", melainkan mencari **payload yang berbeda dari baseline normal**.

---

# 4. Menemukan Channel ICMP

## 4.1 Baseline ICMP

Sebagian besar paket ICMP menggunakan payload pola standar:

```text
10 11 12 13 14 15 ... 47
```

Pola tersebut merupakan payload ping biasa.

Namun, terdapat **13 ICMP echo-request** yang berbeda dari baseline. Paket-paket tersebut berasal dari:

```text
192.168.1.50
```

dan menuju:

```text
10.0.0.99
```

Menariknya, `10.0.0.99` merupakan host yang tidak muncul sebagai destination umum pada trafik lain.

ICMP identifier tetap:

```text
18977
```

sehingga identifier bukan indikator data rahasia. Perbedaannya terdapat pada isi payload.

---

## 4.2 Payload Tersembunyi

Payload ICMP yang menyimpang memiliki struktur:

```text
[2 byte CRC]
[1 byte index]
[1 byte karakter]
```

Contoh awal payload:

```text
65 a8 00 43 ...
```

Interpretasinya:

```text
65 a8    -> CRC-16
00       -> index 0
43       -> ASCII 'C'
```

Byte indeks kemudian meningkat secara berurutan sampai:

```text
00 -> 01 -> 02 -> ... -> 0c
```

Dengan demikian channel ICMP membawa:

```text
index 0 ... 12
```

---

# 5. Validasi CRC

Dua byte pertama bukan bagian dari karakter flag. Keduanya merupakan integrity check.

CRC yang digunakan adalah:

```text
CRC-16/CCITT-FALSE
Initial value = 0xFFFF
```

CRC dihitung terhadap pasangan:

```text
[index, character]
```

Secara konseptual:

```text
CRC = CRC16_CCITT_FALSE(bytes([index, character]))
```

Hal ini sangat berguna ketika melakukan parsing otomatis karena kita dapat membedakan payload data dengan paket decoy.

---

# 6. Menemukan Channel DNS

## 6.1 Filtering

Setelah ICMP selesai dianalisis, pemeriksaan berpindah ke DNS.

Sebagian besar query mengarah ke domain biasa berakhiran:

```text
*.test
```

Akan tetapi terdapat kelompok query menuju:

```text
*.cdn-edge.test
```

dari host:

```text
192.168.1.77
```

Terdapat beberapa label domain yang terlihat tidak biasa, misalnya:

```text
DTM
DmM
DzA
...
```

Sebanyak **13 query** dengan label tersebut merupakan channel sebenarnya.

Sementara label seperti:

```text
cdn
www
fonts
static
edge01
```

merupakan decoy.

---

## 6.2 Encoding DNS

Label berisi data dalam Base64.

Contoh:

```text
DTM
```

Jika ditambahkan padding Base64:

```text
DTM=
```

maka hasil decode menjadi:

```text
0d 33
```

Interpretasi:

```text
0d -> index 13
33 -> ASCII '3'
```

Dengan demikian channel DNS melanjutkan pesan mulai dari:

```text
index 13
```

hingga:

```text
index 25
```

---

# 7. Menemukan Channel HTTP

## 7.1 Menentukan Destination Unik

Pada trafik HTTP terdapat banyak request normal. Namun terlihat kelompok request menuju:

```text
198.51.100.55
```

dengan host:

```text
px.admetrics.test
```

Di antara request tersebut terdapat beberapa `POST` menuju endpoint:

```text
/collect
```

Request lainnya seperti:

```text
GET /track
GET /pixel.gif
```

berfungsi sebagai decoy.

---

## 7.2 Field `px`

POST yang relevan memiliki body JSON seperti:

```json
{"ts":...,"px":"1a75"}
```

Field penting adalah:

```text
px
```

Nilai tersebut berisi:

```text
[index hex][character hex]
```

Contoh:

```text
1a75
```

dipecah menjadi:

```text
1a -> 0x1a -> decimal 26
75 -> ASCII 'u'
```

Maka:

```text
index = 26
character = 'u'
```

Terdapat **13 fragmen HTTP** dengan indeks:

```text
26–38
```

---

# 8. Rekonstruksi Pesan

Sekarang seluruh channel dapat digabungkan.

## Pembagian Indeks

| Indeks | Channel | Sumber |
|---:|---|---|
| `0–12` | ICMP | Payload echo-request khusus |
| `13–25` | DNS | Label Base64 `cdn-edge.test` |
| `26–38` | HTTP | Field `px` pada POST `/collect` |

Total:

```text
13 + 13 + 13 = 39 karakter
```

Urutan global:

```text
0
1
2
...
38
```

Karena setiap fragmen membawa indeks eksplisit, kita tidak perlu mengandalkan timestamp atau urutan host untuk menentukan posisi karakter.

---

# 9. Potongan Data

Bagian awal pesan berasal dari ICMP:

```text
0  -> C
1  -> Y
2  -> B
3  -> E
4  -> R
5  -> L
6  -> E
7  -> A
8  -> G
9  -> U
10 -> E
11 -> {
12 -> d
```

Hasil sementara:

```text
CYBERLEAGUE{d
```

DNS kemudian melanjutkan pesan dari indeks `13` sampai `25`, sedangkan HTTP melanjutkan bagian terakhir sampai indeks `38`.

Jika seluruh karakter disusun ulang berdasarkan indeks:

```text
CYBERLEAGUE{d3c0rr3l4t3d_curr3nts_fl0w}
```

---

# 10. Strategi Investigasi dengan Wireshark

## 10.1 Protocol Hierarchy

Langkah awal:

```text
Statistics
    → Protocol Hierarchy
```

Tujuannya adalah memahami baseline protokol yang terdapat pada capture.

Kemudian periksa:

```text
Statistics
    → Conversations
```

Cari destination atau conversation yang frekuensinya kecil tetapi berbeda dari pola umum.

---

## 10.2 Filtering ICMP

Gunakan:

```bash
tshark -r undertow.pcap \
  -Y 'icmp.type==8 && ip.dst==10.0.0.99' \
  -T fields \
  -e data.data
```

Perintah tersebut menampilkan data payload ICMP yang menuju host mencurigakan.

Fokus pada paket yang tidak menggunakan pola:

```text
10 11 12 ... 47
```

---

## 10.3 Filtering DNS

Gunakan:

```bash
tshark -r undertow.pcap \
  -Y 'dns.flags.response==0 && dns.qry.name contains "cdn-edge"' \
  -T fields \
  -e dns.qry.name
```

Dari hasil ini, filter kembali label yang memiliki karakteristik Base64.

---

## 10.4 Filtering HTTP

Gunakan:

```bash
tshark -r undertow.pcap \
  -Y 'http.request.method=="POST"' \
  -T fields \
  -e http.file_data
```

Kemudian cari request yang memiliki field:

```text
px
```

dan host:

```text
px.admetrics.test
```

---

# 11. Solver

Shared conversation menyebut adanya file solver `undertow_solve.py` yang digunakan pada saat analisis. File attachment tersebut tidak tampil pada snapshot shared chat, sehingga implementasi asli solver tidak dapat direproduksi persis dari shared page.

Namun, berdasarkan struktur data yang berhasil diidentifikasi, solver dapat dibangun dengan dua tahap:

```text
PCAP
 ↓
Parse Ethernet / IPv4
 ↓
Pisahkan ICMP / DNS / HTTP
 ↓
Ekstrak [index, char]
 ↓
Validasi CRC untuk ICMP
 ↓
Decode Base64 untuk DNS
 ↓
Decode hex pair untuk HTTP
 ↓
Gabungkan berdasarkan index
 ↓
Flag
```

## 11.1 Contoh Solver Konseptual

Berikut implementasi Python 3 yang merekonstruksi fragmen dari data yang telah diekstrak:

```python
#!/usr/bin/env python3

import base64
import binascii
import re


def crc16_ccitt_false(data: bytes, init: int = 0xFFFF) -> int:
    crc = init

    for byte in data:
        crc ^= byte << 8

        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    return crc


def parse_icmp_payload(payload: bytes):
    if len(payload) < 4:
        return None

    expected_crc = int.from_bytes(payload[0:2], "big")
    index = payload[2]
    char = payload[3]

    actual_crc = crc16_ccitt_false(bytes([index, char]))

    if actual_crc != expected_crc:
        return None

    return index, chr(char)


def parse_dns_label(label: str):
    try:
        raw = base64.b64decode(label + "===")
    except (ValueError, binascii.Error):
        return None

    if len(raw) != 2:
        return None

    index = raw[0]
    char = raw[1]

    if not (32 <= char <= 126):
        return None

    return index, chr(char)


def parse_http_px(px: str):
    if not re.fullmatch(r"[0-9a-fA-F]{4}", px):
        return None

    raw = bytes.fromhex(px)

    index = raw[0]
    char = raw[1]

    if not (32 <= char <= 126):
        return None

    return index, chr(char)


def rebuild(fragments):
    table = {}

    for index, char in fragments:
        if index in table and table[index] != char:
            raise ValueError(
                f"Konflik pada index {index}: "
                f"{table[index]!r} vs {char!r}"
            )

        table[index] = char

    expected = list(range(39))
    actual = sorted(table)

    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))

        raise ValueError(
            f"Index tidak lengkap. Missing={missing}, Extra={extra}"
        )

    return "".join(table[i] for i in expected)


def main():
    # Fragmen hasil ekstraksi dari ketiga channel.
    # ICMP: index 0-12
    icmp = [
        (0, "C"),
        (1, "Y"),
        (2, "B"),
        (3, "E"),
        (4, "R"),
        (5, "L"),
        (6, "E"),
        (7, "A"),
        (8, "G"),
        (9, "U"),
        (10, "E"),
        (11, "{"),
        (12, "d"),
    ]

    # DNS: index 13-25
    dns = [
        # Isi disesuaikan dengan hasil decode capture.
    ]

    # HTTP: index 26-38
    http = [
        # Isi disesuaikan dengan hasil decode capture.
    ]

    fragments = icmp + dns + http

    # Pastikan setiap index hanya muncul satu kali.
    flag = rebuild(fragments)

    print(f"FLAG: {flag}")


if __name__ == "__main__":
    main()
```

> **Catatan:** blok solver di atas merupakan rekonstruksi metodologi berdasarkan struktur data yang dijelaskan dalam shared chat. Solver attachment asli `undertow_solve.py` tidak tersedia pada snapshot yang dapat diakses, sehingga bagian parser PCAP mentah tidak diklaim sebagai salinan solver asli.

---

# 12. Cara Melakukan Verifikasi Manual

## 12.1 ICMP

Pastikan ditemukan:

```text
index 0–12
```

dan setiap fragmen lolos CRC-16/CCITT-FALSE.

Awal pesan harus menghasilkan:

```text
CYBERLEAGUE{d
```

## 12.2 DNS

Pastikan hanya query dengan pola:

```text
*.cdn-edge.test
```

yang mengandung label Base64 relevan.

Hasil decode harus meneruskan indeks:

```text
13–25
```

## 12.3 HTTP

Pastikan request relevan berasal dari:

```text
px.admetrics.test
```

dengan method:

```text
POST /collect
```

serta field:

```text
px
```

Indeks harus meneruskan:

```text
26–38
```

---

# 13. Kenapa Decoy Dapat Menipu Analisis

Challenge ini sengaja membuat setiap channel terlihat normal ketika dianalisis sendiri.

Contohnya:

### ICMP

Sebagian besar packet memang benar-benar ping normal.

### DNS

Sebagian besar query merupakan nama domain yang tampak valid. Hanya subset kecil yang membawa channel rahasia.

### HTTP

Terdapat banyak request tracking dan pixel yang membuat request `/collect` terlihat seperti telemetri biasa.

Dengan kata lain, indikator utamanya bukan satu paket aneh, tetapi **korelasi lintas protokol**.

---

# 14. Insight Penting

## 14.1 Jangan Hanya Mengandalkan Packet Order

Jika kita langsung membaca packet berdasarkan timestamp, kita bisa mendapatkan susunan yang tidak konsisten.

Solusinya adalah menggunakan metadata yang disisipkan attacker:

```text
index
```

Index tersebut menjadi urutan global sebenarnya.

---

## 14.2 Cari Destination yang Jarang Digunakan

Host berikut adalah indikator penting:

```text
10.0.0.99
198.51.100.55
```

Walaupun jumlah paketnya jauh lebih kecil dibanding trafik normal, host seperti ini sering menjadi petunjuk channel tersembunyi.

---

## 14.3 Payload Lebih Penting daripada Header

Karena header dibuat konsisten, pemeriksaan seperti berikut kurang membantu:

```text
TTL anomaly
TCP flag anomaly
IP option anomaly
```

Sebaliknya, analisis harus diarahkan ke:

```text
payload entropy
payload structure
encoding
repetition
indexing
```

---

# 15. Exploit / Solving Chain

Keseluruhan proses dapat dirangkum sebagai berikut:

```text
undertow.pcap
      │
      ▼
Protocol profiling
      │
      ├───────────────┐
      │               │
      ▼               ▼
 ICMP anomaly      DNS anomaly      HTTP anomaly
      │               │               │
      ▼               ▼               ▼
 CRC + index       Base64           hex pair
      │               │               │
      ▼               ▼               ▼
   0–12            13–25            26–38
      │               │               │
      └───────────────┴───────────────┘
                      │
                      ▼
            Sort by global index
                      │
                      ▼
       CYBERLEAGUE{d3c0rr3l4t3d_curr3nts_fl0w}
```

---

# 16. Hasil Akhir

Flag yang berhasil direkonstruksi adalah:

```text
CYBERLEAGUE{d3c0rr3l4t3d_curr3nts_fl0w}
```

---

# 17. Pembelajaran

Challenge **Undertow** mengajarkan bahwa covert channel tidak selalu terlihat sebagai payload yang sangat mencurigakan. Data dapat disebarkan ke beberapa protokol sehingga masing-masing channel terlihat seperti trafik normal.

Hal terpenting dalam investigasi adalah:

1. membangun baseline trafik normal,
2. mencari destination atau payload yang menyimpang,
3. memahami format encoding yang digunakan,
4. mencari identifier/sequence number tersembunyi,
5. melakukan korelasi lintas protokol,
6. merekonstruksi data berdasarkan metadata, bukan hanya urutan paket.

Pada kasus ini, tiga protokol yang tampak tidak berkaitan ternyata membentuk satu channel exfiltration terpadu.

---

## Flag

```text
CYBERLEAGUE{d3c0rr3l4t3d_curr3nts_fl0w}
```

