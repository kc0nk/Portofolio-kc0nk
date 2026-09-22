# CYBERLEAGUE CTF — Writeup

## Tide Pool (Forensics)

| | |
|---|---|
| **Kategori** | Forensics — Network Forensics (DNS Tunneling / Exfiltration) |
| **Berkas** | `tide-pool.zip` → `tide-pool.pcap` |
| **Server** | – |
| **Format flag** | `CYBERLEAGUE{...}` |
| **Flag** | `CYBERLEAGUE{p0lym0rph1c_tunn3l_tw1n_t1d3s}` |

---

### 1. Deskripsi Soal

> Our SOC flagged a spike in DNS query volume from a workstation on the corporate LAN shortly before an internal service account went quiet. Nothing was ever blocked and nothing looks broken — the traffic never left port 53, and every lookup came back clean. Something still walked out the door under everyone's nose. Here's the capture from the suspect window; find out what the host was really asking for.

Singkatnya: SOC melihat lonjakan volume query DNS dari satu workstation, tepat sebelum sebuah service account internal "diam". Semua trafik tetap di port 53 dan tampak "bersih" (tidak diblokir, tidak error). Tugasnya: cari tahu apa yang sebenarnya "ditanyakan" host tersebut — indikasi kuat DNS tunneling / DNS exfiltration.

---

### 2. Persiapan Lingkungan

Karena tidak ada `tshark`, `capinfos`, maupun `scapy` di sandbox, seluruh analisis dilakukan dengan **parser pcap murni Python 3** (hanya memakai modul `struct`). Ini justru bagus untuk writeup karena semua logika parsing terlihat eksplisit — tidak ada "black box".

```bash
unzip tide-pool.zip
file tide-pool.pcap
# tide-pool.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

---

### 3. Langkah Investigasi

#### 3.1 Profil Capture

Parsing header pcap global (24 byte) lalu setiap record paket (header 16 byte: `ts_sec, ts_usec, incl_len, orig_len` diikuti data paket):

```python
def read_pcap(fn):
    d = open(fn, 'rb').read()
    magic = d[:4]
    end = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    off = 24
    pkts = []
    while off + 16 <= len(d):
        ts_s, ts_us, incl, orig = struct.unpack(end+'IIII', d[off:off+16])
        off += 16
        pkts.append((ts_s + ts_us/1e6, d[off:off+incl]))
        off += incl
    return pkts
```

Hasil profil:

- **878 paket**, durasi capture **~27 detik**
- **100% trafik = UDP/53** antara `192.168.1.50` (host korban) ⇄ `8.8.8.8` (resolver)
- 439 query + 439 response — tidak ada protokol lain sama sekali

Ini konsisten dengan deskripsi soal: "the traffic never left port 53".

#### 3.2 Parser DNS

Ditulis parser DNS message minimal (mendukung name compression `0xC0` pointer) untuk membongkar QNAME, QTYPE, flags, dan seluruh Resource Record dari tiap paket:

```python
def parse_name(msg, off):
    labels = []
    jumped = False
    orig = off
    while True:
        l = msg[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:            # compression pointer
            ptr = ((l & 0x3F) << 8) | msg[off+1]
            if not jumped:
                orig = off + 2
            jumped = True
            off = ptr
            continue
        labels.append(msg[off+1:off+1+l])
        off += 1 + l
    if not jumped:
        orig = off
    return labels, orig

def parse_dns(msg):
    tid, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', msg[:12])
    off = 12
    qs = []
    for _ in range(qd):
        labels, off = parse_name(msg, off)
        qtype, qclass = struct.unpack('>HH', msg[off:off+4]); off += 4
        qs.append((labels, qtype, qclass))
    rrs = []
    for _ in range(an+ns+ar):
        labels, off = parse_name(msg, off)
        t, c, ttl, rdl = struct.unpack('>HHIH', msg[off:off+10]); off += 10
        rdata = msg[off:off+rdl]; off += rdl
        rrs.append((labels, t, c, ttl, rdata))
    return dict(id=tid, flags=flags, qd=qd, an=an, ns=ns, ar=ar, qs=qs, rrs=rrs)
```

Distribusi QTYPE pada 439 query:

| QTYPE | Kode | Jumlah |
|---|---|---|
| A | 1 | 359 |
| AAAA | 28 | 48 |
| NS | 15 | 32 |

#### 3.3 Mengelompokkan Query per Parent Domain

Semua query dikelompokkan berdasarkan "domain induk" (dua/tiga label terakhir setelah subdomain acak). Trafik yang tampak normal (`www`, `api`, `mail`, `docs`, `vpn`, `ldap`, `proxy`, `ntp`, `repo`, `monitor`, `ci`, `dns1/2`, `fonts`, `images`, `static`, `assets` — semuanya di `reef.test`/`reefcdn.test`) mendominasi dan tampak wajar: nama tetap, jumlah query wajar, jawaban A/AAAA konsisten.

Namun muncul **11 subdomain kandidat** dengan pola label pertama yang **selalu berubah-ubah** setiap query (fingerprint klasik DNS tunneling — label unik dipakai untuk membawa data):

```
286 reef.test
 16 update.reef.test
 15 hotfix.reef.test
 14 edge.reefcdn.test
 14 media.reefcdn.test
 13 reefcdn.test
 13 cdn.reefcdn.test
 13 release.reef.test
 12 cache.reef.test
 11 patch.reef.test
 11 telemetry.reef.test
 11 cdn-metrics.reef.test
 10 analytics.reef.test
```

#### 3.4 Menyaring Umpan (Decoy) dari Channel Asli

Untuk setiap dari 11 kandidat, dicatat: bentuk label (hex? base32? acak?), kode respons, dan — kunci penyaringan — **entropi Shannon** serta **rasio karakter printable** dari hasil decode-nya.

```python
def entropy(b):
    c = collections.Counter(b); n = len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())
```

| Subdomain | Bentuk label | Kode Respons | Entropi (bit/byte) | % printable | Verdict |
|---|---|---|---|---|---|
| `edge.reefcdn.test` | hex acak | NOERROR (A) | 5.85 | 35% | **Umpan** |
| `cdn.reefcdn.test` | hex acak | NOERROR (A) | 5.93 | 32% | **Umpan** |
| `media.reefcdn.test` | hex acak | NOERROR (A) | 6.23 | 35% | **Umpan** |
| `hotfix.reef.test` | hex acak | NOERROR (A) | 5.59 | 47% | **Umpan** |
| `update.reef.test` | hex acak | NOERROR (A) | 5.78 | 48% | **Umpan** |
| `patch.reef.test` | hex acak | NOERROR (A) | 5.28 | 36% | **Umpan** |
| `release.reef.test` | hex acak | NOERROR (A) | 5.62 | 35% | **Umpan** |
| `analytics.reef.test` | base32/hex campur, tak konsisten | NXDOMAIN | 4.81 | 34% | **Umpan** |
| `cache.reef.test` | base32/hex campur, tak konsisten | NXDOMAIN | 5.31 | 41% | **Umpan** |
| **`telemetry.reef.test`** | base32 valid | NXDOMAIN + SOA | — | tinggi setelah decode | **Channel 1 (asli)** |
| **`cdn-metrics.reef.test`** | hex valid | NXDOMAIN + SOA | — | tinggi setelah decode | **Channel 2 (asli)** |

Delapan grup pertama punya entropi ~5.3–6.2 bit/byte dan hanya ~35–48% byte-nya printable — ciri khas **data acak** yang sengaja disisipkan sebagai noise/pengalih perhatian. Semua mendapat respons A yang juga tidak bermakna.

Sebaliknya, `telemetry` dan `cdn-metrics` sama-sama:
- Selalu mendapat **NXDOMAIN** dengan record **SOA** identik (tanda resolver "menyerah" mencari nama — wajar untuk domain yang memang tidak pernah didaftarkan, karena tujuannya hanya membawa data, bukan resolusi nama).
- Setelah di-decode base32/hex, hasilnya **ASCII yang bermakna** (bukan noise).

Ini adalah dua **channel data asli** — istilah "polymorphic tunnel" pada flag merujuk pada dua encoding berbeda yang dipakai bergantian, dan "twin tides" merujuk pada dua channel yang harus digabung.

Contoh decode mentah:

```
== telemetry (base32)
a52xgzls -> b'\x07user'
cfrv65dv -> b'\x11c_tu'
ae6xa33p -> b'\x01=poo'
bvcucr2v -> b'\rEAGU'
...

== cdn-metrics (hex)
00686f7374 -> b'\x00host'
0a653b6b65 -> b'\ne;ke'
1072706831 -> b'\x10rph1'
083d737663 -> b'\x08=svc'
...
```

Byte pertama pada tiap chunk bukan bagian data — ia adalah **nomor urut (indeks) rekonstruksi**.

#### 3.5 Merakit Data Tersembunyi

Skema tunneling-nya:

- Setiap label channel asli berformat `[1 byte indeks][4 byte data]`.
- `telemetry` (base32) membawa indeks **ganjil**, `cdn-metrics` (hex) membawa indeks **genap** — dua encoding berbeda dipakai bergantian per potongan (inilah makna *polymorphic*).
- Total 22 chunk (11 dari tiap channel), indeks 0–21 **lengkap tanpa celah maupun duplikat** — bukti rekonstruksi benar.

```python
chunks = {}
for i, l in queries():
    lab, sub = l[0], l[1]
    if sub == 'telemetry':
        raw = b32(lab)                      # base32 decode
    elif sub == 'cdn-metrics':
        raw = binascii.unhexlify(lab)       # hex decode
    else:
        continue
    chunks[raw[0]] = raw[1:]                # byte pertama = indeks urut

msg = b''.join(chunks[k] for k in sorted(chunks))
print(msg.decode())
```

**Output:**

```
host=pool-srv.reef.internal;user=svc_tide;key=CYBERLEAGUE{p0lym0rph1c_tunn3l_tw1n_t1d3s}
```

Inilah yang "berjalan keluar" tanpa ketahuan: kredensial service account (`svc_tide`) beserta flag, dibocorkan lewat nama-nama DNS yang selalu NXDOMAIN — semua lookup "kembali bersih" persis seperti disebut di deskripsi soal, karena tidak ada resolusi nama yang berhasil untuk dicurigai; datanya justru ada di dalam *query* itu sendiri, bukan di respons.

#### 3.6 Verifikasi: Tidak Ada Flag Tandingan

Untuk memastikan 9 channel umpan lainnya benar-benar tidak menyimpan data tersembunyi lain, dilakukan pengecekan ulang entropi/printable-ratio secara sistematis, pencarian string `CYBERLEAGUE` mentah di seluruh file pcap, serta pengecekan Additional/Authority records dan tipe RR pada seluruh respons:

```
edge       n=14 bytes=72  printable=0.35 entropy=5.85
cdn        n=13 bytes=74  printable=0.32 entropy=5.93
media      n=14 bytes=96  printable=0.35 entropy=6.23
hotfix     n=15 bytes=60  printable=0.47 entropy=5.59
update     n=16 bytes=64  printable=0.48 entropy=5.78
patch      n=11 bytes=44  printable=0.36 entropy=5.28
release    n=13 bytes=52  printable=0.35 entropy=5.62
analytics  n=10 bytes=32  printable=0.34 entropy=4.81
cache      n=12 bytes=41  printable=0.41 entropy=5.31

CYBERLEAGUE in raw pcap: False
non-zero ar/ns in queries: 0
```

Semua channel umpan konsisten berentropi tinggi (noise acak) — mengonfirmasi hanya `telemetry` + `cdn-metrics` yang merupakan channel exfiltration asli.

---

### 4. Solver Otomatis

Skrip Python 3 mandiri (tanpa dependensi eksternal) untuk mereproduksi solusi dari awal:

```python
#!/usr/bin/env python3
"""
Tide Pool - CYBERLEAGUE (Forensics / Network Forensics: DNS tunneling)
Pemakaian: python3 solve_tide_pool.py tide-pool.pcap
"""
import sys, struct, base64, binascii

def read_pcap(path):
    d = open(path, "rb").read()
    end = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    off, out = 24, []
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack(end + "IIII", d[off:off + 16])
        off += 16
        out.append(d[off:off + incl])
        off += incl
    return out

def dns_qnames(pkt):
    """Kembalikan list label query (str) jika paket adalah query DNS UDP/53."""
    if struct.unpack(">H", pkt[12:14])[0] != 0x0800:      # IPv4 saja
        return []
    ihl = (pkt[14] & 0xF) * 4
    if pkt[14 + 9] != 17:                                  # UDP
        return []
    udp = pkt[14 + ihl:]
    if struct.unpack(">H", udp[2:4])[0] != 53:             # arah -> server
        return []
    msg = udp[8:]
    qd = struct.unpack(">H", msg[4:6])[0]
    off, names = 12, []
    for _ in range(qd):
        labels = []
        while msg[off]:
            n = msg[off]
            labels.append(msg[off + 1:off + 1 + n].decode("latin1"))
            off += 1 + n
        off += 1 + 4                                       # NUL + QTYPE + QCLASS
        names.append(labels)
    return names

def b32(s):
    s = s.upper()
    return base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))

def main(path):
    chunks = {}
    for pkt in read_pcap(path):
        for lab in dns_qnames(pkt):
            if len(lab) < 3:
                continue
            first, sub = lab[0], lab[1]
            if sub == "telemetry":        # channel 1: base32 -> [idx][4B data] (idx ganjil)
                raw = b32(first)
            elif sub == "cdn-metrics":    # channel 2: hex    -> [idx][4B data] (idx genap)
                raw = binascii.unhexlify(first)
            else:                         # channel lain = umpan (noise acak)
                continue
            chunks[raw[0]] = raw[1:]

    order = sorted(chunks)
    assert order == list(range(len(order))), f"indeks tidak lengkap: {order}"
    msg = b"".join(chunks[i] for i in order).decode()
    print("[+] chunk  :", len(chunks))
    print("[+] pesan  :", msg)
    print("[+] FLAG   :", msg.split("key=")[1])

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tide-pool.pcap")
```

**Eksekusi:**

```bash
$ python3 solve_tide_pool.py tide-pool.pcap
[+] chunk  : 22
[+] pesan  : host=pool-srv.reef.internal;user=svc_tide;key=CYBERLEAGUE{p0lym0rph1c_tunn3l_tw1n_t1d3s}
[+] FLAG   : CYBERLEAGUE{p0lym0rph1c_tunn3l_tw1n_t1d3s}
```

#### Padanan perintah `tshark`

Meski tidak tersedia di lingkungan analisis ini, berikut padanan standar dengan `tshark` untuk verifikasi silang di mesin lain:

```bash
# Query per parent domain (deteksi tunneling)
tshark -r tide-pool.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name \
  | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}' | sort | uniq -c | sort -rn

# Ambil label kedua channel asli
tshark -r tide-pool.pcap -Y 'dns.qry.name contains "telemetry.reef.test"'   -T fields -e dns.qry.name
tshark -r tide-pool.pcap -Y 'dns.qry.name contains "cdn-metrics.reef.test"' -T fields -e dns.qry.name

# Bandingkan kode respons (rcode 3 = NXDOMAIN)
tshark -r tide-pool.pcap -Y "dns.flags.response==1" -T fields -e dns.qry.name -e dns.flags.rcode
```

---

### 5. Ringkasan (Indicator of Compromise)

| Item | Detail |
|---|---|
| Host tersangka | `192.168.1.50` |
| Resolver | `8.8.8.8` |
| Channel exfiltration | `*.telemetry.reef.test` (base32) + `*.cdn-metrics.reef.test` (hex) |
| Teknik | DNS tunneling via NXDOMAIN, label = `[indeks][4B data]`, dua encoding bergantian |
| Payload yang bocor | `host=pool-srv.reef.internal;user=svc_tide;key=CYBERLEAGUE{...}` |
| Akun terdampak | `svc_tide` (service account) |
| Rekomendasi mitigasi | Alert pada rasio NXDOMAIN tinggi per-domain-induk dari satu host; rotasi kredensial `svc_tide`; blok/sinkhole `*.telemetry.reef.test` dan `*.cdn-metrics.reef.test` |

---

### 6. Flag

```
CYBERLEAGUE{p0lym0rph1c_tunn3l_tw1n_t1d3s}
```
