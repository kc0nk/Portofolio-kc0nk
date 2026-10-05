---
ctf: "BreakTheSyntax CTF 2026 (BtSCTF)"
kategori: "Forensics (Memory + Network)"
challenge: "FCP"
flag: "BtSCTF{more_like_midcp_67}"
teknik: "Dump memory server Go dengan gcore, temukan RSA private key in-memory lewat pola layout big.Int, lalu dekripsi sesi TLS yang di-resume via EMS PRF"
---

# FCP — BreakTheSyntax CTF 2026 (Forensics: Memory + Network)

**Info soal:** Hard, target Linux.

## Deskripsi Singkat

Kita diberikan binary server MCP ("Model Context Protocol") berbasis Go, plus sebuah PCAP dari seseorang yang memakainya sebelumnya. Terkubur di dalam capture ada satu panggilan `get_flag` — tapi endpoint `get_flag` di server live sudah ditulis ulang untuk sekadar mengembalikan `"no"`, jadi menjalankannya ulang tidak berguna. Tantangannya adalah mendekripsi traffic historis tersebut. Dua keputusan desain spesifik membuat ini mungkin sekaligus tidak sepele.

## Recon — Setup

Binary ini sengaja memaksa cipher suite TLS ke `TLS_RSA_WITH_AES_128_CBC_SHA`. Ini adalah RSA key exchange klasik — client memilih pre-master secret acak, mengenkripsinya dengan public key RSA milik server, lalu mengirim ciphertext-nya di ClientKeyExchange. **Kalau kita memegang RSA private key milik server, kita bisa mendekripsi PMS dari PCAP secara retroaktif.** Inilah tepatnya alasan TLS 1.3 membuang RSA key exchange dan beralih ke (EC)DHE yang forward-secret — serangan "tangkap sekarang, dekripsi nanti" (harvest now, decrypt later) langsung berlaku begitu kamu memilih `TLS_RSA_*`.

**Komplikasi pertama:** server ini **tidak menyimpan private key-nya di disk.** Ia membangkitkan RSA key 2048-bit baru setiap kali start, dan key itu hanya hidup di memori proses. Jadi kita harus mengekstrak key dari instance yang sedang berjalan, lalu memakainya untuk mendekripsi sesi historis.

**Komplikasi kedua:** hanya sesi TLS **pertama** di PCAP yang melakukan full handshake. Setiap stream berikutnya adalah **session resumption dengan Extended Master Secret (EMS)**. Tidak ada `ClientKeyExchange` baru di sana — jadi sekalipun sudah punya RSA key, mendekripsi sesi yang di-resume butuh master secret itu sendiri.

**Jalur solusi lengkap:**

1. Dump heap server yang sedang berjalan dengan `gcore`
2. Cari RSA key in-memory dengan mengenali layout limb `big.Int` milik Go
3. Dekripsi pre-master secret milik stream 1 dengan private key yang ditemukan
4. Turunkan master secret lewat EMS PRF
5. Pakai ulang master secret itu untuk mendekripsi setiap sesi resumption di dalam capture

## Analisis

### Langkah 1 — Snapshot Memori Server

File core ELF biasa memberi kita semua yang dialokasikan Go di heap, termasuk instance `*big.Int` yang masih hidup.

```bash
$ ./fcp-server &
[1] 12847
$ sudo gcore -o core 12847
[Thread debugging using libthread_db enabled]
...
Saved corefile core.12847
```

`core.12847` adalah ELF biasa yang bisa diperiksa debugger mana pun, tapi yang lebih penting kita bisa memindainya sebagai raw bytes.

### Langkah 2 — Menemukan RSA Key Lewat Layout `big.Int`

Ini bagian paling menarik dari soal ini. `crypto/rsa.PrivateKey` milik Go menyimpan parameternya sebagai `*big.Int`. Secara internal, `big.Int` hanyalah struct pembungkus `nat`, yang pada `amd64` berupa `[]Word` — slice limb `uint64` dalam **urutan little-endian**. Modulus 2048-bit karenanya hidup sebagai persis **32 word 8-byte berurutan = 256 byte berdampingan** di heap Go.

Jadi, daripada melakukan disassembly, kita perlakukan dump-nya sebagai string byte panjang dan geser window 256-byte melintasinya. Di setiap offset, kita reinterpretasi window itu sebagai integer little-endian 2048-bit dan bertanya: *apakah ini terlihat seperti modulus RSA?*

Sebuah `N` RSA 2048-bit yang asli:

- Memiliki panjang bit 2040–2048 (bit teratas set)
- Ganjil
- Tidak punya faktor prima kecil

False positive sangat jarang — byte heap acak nyaris tidak pernah memenuhi ketiga kondisi ini sekaligus.

```python
def words_to_int(b):
    """Reinterpretasi 256 byte sebagai nat milik big.Int Go: 32 limb uint64 little-endian."""
    n = 0
    for i in range(0, 256, 8):
        n |= int.from_bytes(b[i:i+8], "little") << (i * 8)
    return n

dump = open("core.12847", "rb").read()
candidates = []
for off in range(0, len(dump) - 256, 8):       # align 8-byte agar cocok dengan allocator Go
    w = dump[off:off+256]
    n = words_to_int(w)
    if n.bit_length() not in range(2040, 2049):
        continue
    if n % 2 == 0:
        continue
    candidates.append((off, n))
```

Eksponen privat `D` hidup berdekatan di heap dengan layout 256-byte yang sama, jadi pada pass kedua, setiap kandidat `N` dipasangkan dengan kandidat `D` dan dicoba faktorisasi `N`-nya dari tuple `(e, d, n)`.

**Tips: memulihkan `p, q` dari `(e, d, n)`.** Ini adalah rutin textbook standar: karena `e·d ≡ 1 (mod λ(n))`, nilai `k = e·d − 1` adalah kelipatan `λ(n)`. Dengan membagi dua `k` berulang-ulang dan mengeksponensiasi basis acak, pada akhirnya akan diperoleh akar kuadrat non-trivial dari 1 modulo `n` — dan `gcd(x − 1, n)` kemudian adalah `p` atau `q`. Tidak perlu faktorisasi `n` dari nol.

```python
import random
from math import gcd

def factor_from_ed(n, e, d):
    k = e * d - 1
    while k % 2 == 0:
        k //= 2
    while True:
        g = random.randrange(2, n - 1)
        t = k
        while t < e * d:
            x = pow(g, t, n)
            if x != 1 and x != n - 1 and pow(x, 2, n) == 1:
                p = gcd(x - 1, n)
                return p, n // p
            t *= 2
```

Dengan `(n, e, d, p, q)` kita bisa merakit PEM:

```python
from Crypto.PublicKey import RSA
key = RSA.construct((n, e, d, p, q))
open("server.key", "wb").write(key.export_key("PEM"))
```

### Langkah 3 — Dekripsi Sesi Pertama

Stream 1 melakukan full handshake. Berikan key hasil pemulihan ke Wireshark/tshark lewat preference `tls.keys_list`, dan sesi pertama langsung terdekripsi bersih:

```bash
$ tshark -r capture.pcap \
    -o "tls.keys_list:any,443,http,server.key" \
    -V \
    | head -200
```

Ini berhasil karena kita punya ciphertext `ClientKeyExchange` dari sesi itu, dan RSA private key hasil pemulihan mendekripsinya untuk memulihkan pre-master secret. Dari situ, `tshark` menurunkan master secret memakai PRF standar TLS 1.2 dan mendekripsi record-nya.

Yang **tidak** ikut terdekripsi adalah stream 2 sampai N — semuanya memakai ulang sesi pertama lewat TLS session resumption dengan ekstensi **Extended Master Secret**. Tanpa `ClientKeyExchange` baru, tidak ada PMS untuk didekripsi. RSA key saja sudah tidak cukup lagi.

### Langkah 4 — Merekonstruksi Master Secret untuk Setiap Sesi Resumption

Dengan Extended Master Secret berlaku (RFC 7627), master secret diturunkan sebagai:

```
master_secret = PRF(pre_master_secret, "extended master secret", session_hash)
```

Di mana `session_hash = SHA256(seluruh pesan handshake dari ClientHello sampai ClientKeyExchange digabung, header record-layer dibuang)`.

Kita bisa menghitungnya langsung untuk stream 1, karena kita sudah punya PMS-nya:

```python
from Crypto.Cipher import PKCS1_v1_5
pms = PKCS1_v1_5.new(key).decrypt(client_key_exchange_blob, None)
```

Lalu implementasikan PRF TLS 1.2 (HMAC-SHA256 sebagai PRF dasar, karena suite yang dinegosiasikan memakai SHA256):

```python
import hmac, hashlib

def p_hash(secret, seed, length):
    out = b""
    a = hmac.new(secret, seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return out[:length]

def tls_prf(secret, label, seed, length):
    return p_hash(secret, label + seed, length)

master_secret = tls_prf(pms, b"extended master secret", session_hash, 48)
```

## Eksploitasi / Solusi

Sekarang bagian intinya. **TLS session resumption pada dasarnya adalah "pakai master secret yang sama dengan sesi sebelumnya".** Setiap sesi resumption di PCAP ini berbagi `master_secret` yang sama, yang baru saja kita hitung. Seluruh tujuan resumption memang untuk melewati key exchange yang mahal dan memakai ulang secret yang sudah ditetapkan. Jadi kita keluarkan satu baris `SSLKEYLOGFILE` per `ClientHello` di dalam capture, semuanya memakai MS yang sama:

```
CLIENT_RANDOM <client_random_stream_1> <master_secret>
CLIENT_RANDOM <client_random_stream_2> <master_secret>
CLIENT_RANDOM <client_random_stream_3> <master_secret>
CLIENT_RANDOM <client_random_stream_4> <master_secret>
CLIENT_RANDOM <client_random_stream_5> <master_secret>
...
```

Setiap entri adalah `CLIENT_RANDOM` diikuti 32-byte client random dari `ClientHello` stream tersebut, lalu master secret 48-byte. Berikan file ini ke Wireshark lewat `Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename`, reload PCAP-nya, dan setiap stream langsung terdekripsi.

**Menemukan flag.** Menelusuri application data yang sudah terdekripsi, stream 5 membawa panggilan MCP `get_flag` yang asli — ditangkap *sebelum* server ditulis ulang untuk mengembalikan `"no"`.

```
BtSCTF{more_like_midcp_67}
```

## Catatan / Pelajaran

1. **Go tidak membersihkan (scrub) materi rahasia dari heap.** Prima RSA, round key AES, dan secret penandatanganan JWT semuanya tetap tersisa setelah operasi kriptografi yang memakainya selesai. Modulus 2048-bit adalah blob little-endian ter-align 256-byte dan bisa dikenali tanpa simbol debug sama sekali.
2. **Cipher suite `TLS_RSA_*` bisa didekripsi secara pasif selamanya kalau kamu pernah memegang key server.** Ini persis serangan "harvest now, decrypt later" yang dirancang untuk dicegah TLS 1.3 dengan menghapus RSA key exchange. Kalau kamu menjalankan apa pun yang bisa memaku suite TLS — proxy STARTTLS, client mTLS custom, service internal — pastikan hanya memakai suite `ECDHE` atau `DHE`.
3. **Session resumption adalah pengganda dampak (multiplier).** Begitu master secret satu sesi berhasil dipulihkan, setiap sesi resumption di dalam capture terdekripsi secara gratis. Ini berlaku baik untuk abbreviated handshake (resumption via session ID) maupun resumption PSK/`SessionTicket`. Secara operasional, kalau kamu curiga TLS-mu bocor, rotasi key **dan** invalidasi semua cache sesi.
4. **EMS tidak menolong di sini** karena kita sudah punya PMS di baliknya. EMS mengikat master secret pada transkrip handshake, melindungi dari serangan sinkronisasi seperti Triple Handshake — tapi tidak menambah forward secrecy. RSA statis + EMS tetap serapuh RSA statis tanpa EMS begitu key server bocor.

## Flag

```
BtSCTF{more_like_midcp_67}
```
