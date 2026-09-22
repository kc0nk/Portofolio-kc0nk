# Writeup: Something's Fishy

**Kategori:** Reverse Engineering / Network Forensics
**Kesulitan:** Easy–Medium
**Flag:** `CYBERLEAGUE{fr4gm3nt3d_p0sts_r3qu1r3_p4t13nc3}`

---

## 1. Deskripsi Soal

> IT flagged unusual outbound traffic from the office network overnight, all of it originating from the smart aquarium controller in the break room. Nobody has touched that thing since it was installed, and it has no business talking to anything outside the building. A network tap caught the whole session before the connection dropped. Dig through the capture and work out what walked out of the office.

**Berkas yang diberikan:** `tank-telemetry.zip` → berisi `tank-telemetry.pcap` (824 paket, ~87 KB).

Tidak ada biner untuk di-reverse di sini — semua "logika" yang harus dibalikkan terletak pada bagaimana data disusun dan disamarkan di dalam traffic jaringan. Ini pada dasarnya soal forensik jaringan yang dikemas dengan judul kategori Reverse Engineering, karena kita harus *me-reverse-engineer* skema fragmentasi + encoding yang dipakai si malware/firmware nakal untuk mengeksfiltrasi data.

---

## 2. Setup Awal

Karena sandbox analisis tidak memiliki `tshark`/`scapy`, parsing dilakukan murni dengan Python 3 stdlib (`struct`) untuk membaca header pcap classic (magic `d4 c3 b2 a1`, little-endian, format record `ts_sec, ts_usec, incl_len, orig_len` diikuti data Ethernet).

```bash
unzip -l tank-telemetry.zip
file tank-telemetry.pcap
# tank-telemetry.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet)
```

Langkah pertama: profil protokol dan host yang terlibat.

```python
import struct, collections

def read_pcap(path):
    d = open(path, "rb").read()
    off = 24  # lewati global header 24 byte
    while off + 16 <= len(d):
        ts_s, ts_us, incl, _ = struct.unpack("<IIII", d[off:off+16])
        off += 16
        yield ts_s + ts_us/1e6, d[off:off+incl]
        off += incl
```

Hasil profil:

| Sumber | Perilaku |
|---|---|
| `192.168.1.105` | Browsing biasa ke situs-situs populer (Google, GitHub, dsb.) — **noise**, workstation pengguna biasa. |
| `192.168.1.40` (**smart aquarium controller**) | ICMP ping ke gateway, DNS lookup ke domain "aqctl", dan HTTP request ke beberapa host `*.aqctl.net` / `aquamonitor.io`. |

`192.168.1.40` adalah aktor yang disebut di deskripsi soal — controller akuarium yang "tidak seharusnya bicara ke luar gedung".

---

## 3. Analisis Traffic dari 192.168.1.40

### 3.1 ICMP — Umpan/Merah Herring

```
192.168.1.40 -> 192.168.1.1  type=8 (echo request)  data: 8 byte
192.168.1.1  -> 192.168.1.40 type=0 (echo reply)     data: 8 byte (sama persis)
```

8 byte payload ICMP standar Linux `ping` sebenarnya adalah **timestamp `double` (little-endian)**, dikonfirmasi dengan:

```python
>>> struct.unpack('>d', b'A\xd9\xads%\x88\xa9b')[0]
1723190422.1353383
```

Ini timestamp Unix yang valid (26 Agustus 2024-ish), bukan data tersembunyi — cukup ping biasa dari sistem yang mengecek konektivitas gateway. **Bukan bagian dari eksfiltrasi.**

### 3.2 DNS

```
api.aquamonitor.io
telemetry.aqctl.net   (x4)
firmware.aqctl.net
metrics.aqctl-cdn.net
```

Empat host berbeda dipanggil oleh controller. Ini penting karena nantinya kita akan menemukan **dua host umpan (decoy)** yang sengaja disisipkan untuk mengelabui analis.

### 3.3 HTTP — Traffic "Normal" (Telemetry Sah)

Sebagian besar POST ke `telemetry.aqctl.net` berisi telemetry sensor akuarium yang wajar:

```
POST /v2/telemetry/push HTTP/1.1
Host: telemetry.aqctl.net
Content-Type: application/x-www-form-urlencoded

payload=eyJ0ZW1wIjoyNS41LCJwaCI6Ny4wMSwidHVyYmlkaXR5IjoxLjU5LCJ0cyI6MTcyMzE5MDQxNn0=
```

Decode base64 → `{"temp":25.5,"ph":7.01,"turbidity":1.59,"ts":1723190416}`. Ini data sensor asli (suhu, pH, kekeruhan air). **Noise**, muncul berulang kali sepanjang capture sebagai kamuflase.

### 3.4 HTTP — Umpan #1: `firmware.aqctl.net`

```
GET /v1/update/check?model=AQ-200&ver=2.1.4 HTTP/1.1
Host: firmware.aqctl.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)   <-- beda! bukan "AquaCtl/2.1.4"

HTTP/1.1 403 Forbidden
<html>...<!-- debug: flag=CYBERLEAGUE{n0t_th1s_0n3_f1sh} --></html>
```

Flag palsu tersemat langsung di komentar HTML, disajikan sangat mudah ditemukan (grep `CYBERLEAGUE` akan langsung nemu ini). Dua kejanggalan yang mengonfirmasi ini decoy:
1. **User-Agent tidak konsisten** — request lain dari device ini selalu `AquaCtl/2.1.4 (Linux; IoT)`, tapi request ini pakai UA browser Windows.
2. Nama flag-nya sendiri secara harfiah bilang `n0t_th1s_0n3` ("bukan yang ini").

### 3.5 HTTP — Umpan #2: `metrics.aqctl-cdn.net`

```
POST /v2/telemetry/push HTTP/1.1
Host: metrics.aqctl-cdn.net

seq=0&payload=Q1lCRVJMRUFHVUV7ZDNjMHlfdDNsM20zdHJ5X24wcDN9
```

Decode base64 → `CYBERLEAGUE{d3c0y_t3l3m3try_n0p3}` — langsung berupa flag utuh dalam satu paket, decode sekali langsung selesai. Ini **decoy kedua**, dikenali dari:
- Host-nya `aqctl-**cdn**.net`, bukan `aqctl.net` — typosquat/lookalike domain.
- Isinya sendiri (`d3c0y_t3l3m3try_n0p3` = "decoy telemetry nope") secara eksplisit memberi tahu bahwa ini jebakan.
- Cuma satu chunk (`seq=0` doang, tak berlanjut), sementara chunk asli tersebar di tiga request.

### 3.6 HTTP — Data Eksfiltrasi Sesungguhnya

Filter ke `telemetry.aqctl.net` (host asli) yang punya parameter `seq=`, karena telemetry sah tidak pernah punya field `seq`:

| seq | Endpoint | Payload mentah | Encoding | Hasil decode |
|---|---|---|---|---|
| 0 | `/v2/telemetry/push` | `Q1lCRVJMRUFHVUV7ZnI0` | Base64 | `CYBERLEAGUE{fr4` |
| 1 | `/v2/telemetry/batch` | `676d336e7433645f70307374735f72` | Hex | `gm3nt3d_p0sts_r` |
| 2 | `/v2/telemetry/sync` | `3qu1r3_p4t13nc3%7D` | URL-encode + plain | `3qu1r3_p4t13nc3}` |

Tiga hal yang membuat ini terlihat "acak" pada pandangan pertama namun sebenarnya sistematis:
- **Endpoint berganti-ganti** (`push` → `batch` → `sync`) — teknik meniru variasi API yang sah agar tidak mencolok di log.
- **Encoding tiap chunk berbeda** (base64 → hex → plain/URL-encoded) — kemungkinan untuk menghindari deteksi signature-based yang hanya mencari satu pola encoding.
- **Field `seq=N`** eksplisit menunjukkan urutan penggabungan — inilah kunci penyusunan ulang.

---

## 4. Strategi Reversing / Pemulihan Data

Langkah logis untuk merekonstruksi flag:

1. **Rekonstruksi stream TCP** dari paket mentah pcap (gabungkan payload per koneksi berdasarkan tuple `(src, sport, dst, dport)`).
2. **Filter berdasarkan sumber**: hanya `192.168.1.40` (device tersangka) sebagai pengirim.
3. **Filter berdasarkan Host header**: buang `firmware.aqctl.net` dan `metrics.aqctl-cdn.net` (decoy), pakai hanya `telemetry.aqctl.net` (host asli, konsisten dengan traffic sensor sah).
4. **Filter berdasarkan bentuk request**: hanya POST yang punya parameter `seq=` — pembeda antara telemetry sah (isinya JSON base64 tanpa `seq`) dan chunk eksfiltrasi.
5. **Decode adaptif per-chunk**: karena tiap chunk pakai encoding berbeda, decoder harus mencoba berurutan:
   - URL-decode dulu (`%7D` → `}`)
   - Jika seluruhnya karakter hex dan panjang genap → decode hex
   - Jika seluruhnya alfabet base64 dan panjang kelipatan 4 → coba decode base64, terima hanya jika hasilnya printable ASCII
   - Selain itu → anggap plain text
6. **Urutkan berdasarkan `seq`** (0, 1, 2, ...) dan **gabungkan (concatenate)** hasil decode-nya.

Validasi bahwa urutan benar: hasil gabungan harus membentuk kalimat leetspeak yang koheren secara semantik — `fr4gm3nt3d_p0sts_r3qu1r3_p4t13nc3` = "fragmented posts require patience", yang justru merupakan petunjuk meta tentang teknik yang dipakai soal ini (data dipecah ke banyak post, jangan buru-buru).

---

## 5. Solver Script

```python
#!/usr/bin/env python3
"""
Something's Fishy - solver (CYBERLEAGUE CTF)
Pure Python 3, tanpa dependensi eksternal.
Usage: python3 solve.py tank-telemetry.pcap
"""
import sys, re, struct, base64, binascii
from urllib.parse import unquote_to_bytes, parse_qs

EXFIL_HOST = "telemetry.aqctl.net"   # host C2 asli (bukan aqctl-cdn / firmware)
DEVICE_IP  = "192.168.1.40"          # smart aquarium controller


def read_pcap(path):
    d = open(path, "rb").read()
    endian = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    off = 24
    while off + 16 <= len(d):
        ts_s, ts_us, incl, _ = struct.unpack(endian + "IIII", d[off:off+16])
        off += 16
        yield ts_s + ts_us / 1e6, d[off:off+incl]
        off += incl


def tcp_segments(pkts):
    for t, p in pkts:
        if p[12:14] != b"\x08\x00" or p[23] != 6:
            continue
        l4 = 14 + (p[14] & 0xF) * 4
        sp, dp, seq, _, doff = struct.unpack("!HHIIB", p[l4:l4+13])
        payload = p[l4 + (doff >> 4) * 4:]
        if payload:
            yield (t, ".".join(map(str, p[26:30])), ".".join(map(str, p[30:34])),
                   sp, dp, seq, payload)


def smart_decode(s: bytes) -> bytes:
    """Tiap chunk memakai encoding berbeda: URL-encode -> hex -> base64 -> plain."""
    s = unquote_to_bytes(s)
    if re.fullmatch(rb"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return binascii.unhexlify(s)
    if re.fullmatch(rb"[A-Za-z0-9+/=]+", s) and len(s) % 4 == 0:
        try:
            dec = base64.b64decode(s, validate=True)
            if all(32 <= c < 127 for c in dec):
                return dec
        except Exception:
            pass
    return s


def main(path):
    chunks = {}
    for t, src, dst, sp, dp, seq, payload in tcp_segments(read_pcap(path)):
        if src != DEVICE_IP or dp != 80 or not payload.startswith(b"POST "):
            continue
        head, _, body = payload.partition(b"\r\n\r\n")
        host = re.search(rb"Host: ([^\r]+)", head).group(1).decode()
        if host != EXFIL_HOST:                   # buang decoy metrics.aqctl-cdn.net
            continue
        qs = parse_qs(body.decode(), keep_blank_values=True)
        if "seq" not in qs:                      # telemetry normal tidak punya seq
            continue
        n = int(qs["seq"][0])
        raw = body.split(b"payload=", 1)[1]      # ambil mentah, smart_decode urus URL-decode
        chunks[n] = smart_decode(raw)
        print(f"[seq={n}] {head.split(b' ')[1].decode():<22} {raw.decode():<40} -> {chunks[n].decode()}")

    flag = b"".join(chunks[k] for k in sorted(chunks)).decode()
    print("\nFLAG:", flag)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tank-telemetry.pcap")
```

### Output aktual saat dijalankan

```
[seq=0] /v2/telemetry/push    Q1lCRVJMRUFHVUV7ZnI0                     -> CYBERLEAGUE{fr4
[seq=1] /v2/telemetry/batch   676d336e7433645f70307374735f72           -> gm3nt3d_p0sts_r
[seq=2] /v2/telemetry/sync    3qu1r3_p4t13nc3%7D                       -> 3qu1r3_p4t13nc3}

FLAG: CYBERLEAGUE{fr4gm3nt3d_p0sts_r3qu1r3_p4t13nc3}
```

---

## 6. Ringkasan Teknik yang Dipelajari

| Teknik | Penerapan di soal ini |
|---|---|
| **Traffic profiling** | Memisahkan device mencurigakan (`.40`) dari noise workstation biasa (`.105`) |
| **Steganografi timestamp di ICMP payload** | Dicek dan dikonfirmasi *bukan* channel eksfiltrasi (false lead yang perlu dieliminasi) |
| **Domain lookalike / typosquatting** (`aqctl-cdn.net` vs `aqctl.net`) | Salah satu dari dua decoy flag |
| **HTML comment injection** pada response error | Decoy flag kedua, dikenali dari User-Agent yang tidak konsisten |
| **Multi-encoding chunk splitting** (base64 / hex / plain URL-encoded, dipisah lewat parameter `seq`) | Skema eksfiltrasi sesungguhnya — data dipecah agar tidak match satu signature deteksi, dan disusun ulang berdasarkan urutan eksplisit |
| **TCP stream reassembly manual** | Diperlukan karena tanpa tshark/scapy, payload HTTP harus direkonstruksi langsung dari header pcap + IP + TCP |

**Pelajaran inti:** jangan langsung percaya pada flag pertama yang ditemukan lewat `grep -r CYBERLEAGUE`. Soal ini sengaja menaruh dua flag umpan yang mudah ditemukan (di komentar HTML dan di satu paket base64 tunggal) untuk menyaring peserta yang tidak memverifikasi konsistensi host/User-Agent sebelum submit.
