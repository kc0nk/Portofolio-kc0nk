---
ctf: "BDSec CTF 2026"
kategori: "Reverse Engineering"
challenge: "Night Shift"
flag: "BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}"
teknik: "5 worker pthread didispatch oleh 8-token 'shift code'; brute-force 5^8=390.625 urutan di Python menemukan satu schedule unik yang cocok 4 target state 32-bit + FNV hash"
---

# Night Shift — BDSec CTF 2026 (Reverse Engineering, 100 poin)

## Deskripsi Singkat

ELF PIE x86-64 **stripped**; import `pthread_create/join/mutex_lock/cond_wait/broadcast/strtok_r/strtoul/fgets`. `rabin2 -i` memunculkan import ini saja sudah menamai seluruh bentuk input-nya: "token terpisah-spasi diparsing sebagai unsigned integer yang didispatch ke worker pthread".

## Analisis

`main` membaca satu baris, mentokenisasi dengan `strtok_r`, mensyaratkan tepat 8 token masing-masing `<= 4`. State bersama diinisialisasi dari `.rodata:0x2170` (`s0..s3 = 0x13579bdf, 0x2468ace0, 0x0badf00d, 0xc001d00d`; `h = 0x811c9dc5` — basis offset FNV-1a). Lima worker thread didispatch oleh urutan token user; tiap thread menunggu `pthread_cond_wait` sampai assignment-nya cocok dengan ID worker-nya, lalu menjalankan blok update dari jump table di `0x2020` (worker `0..4 → 0x1930, 0x1910, 0x18f0, 0x1820, 0x1958`).

Setelah seluruh 8 assignment, `main` mengecek `(s0,s1) == 0x75a2cc729c8a97dc`, `(s2,s3) == 0x4969e73d1d87ef0f`, `h == 0x4455cee8`, `index == 8`.

## Eksploitasi / Solusi

Ruang pencariannya cuma **390.625 urutan** (`5^8`). Simulasi eksaustif di Python atas kelima blok update worker menemukan schedule unik dalam kurang dari satu detik:

```python
for sched in itertools.product(range(5), repeat=8):
    s0, s1, s2, s3, h, idx = INIT_STATE
    for worker_id in sched:
        s0, s1, s2, s3, h, idx = apply_worker_update(worker_id, s0, s1, s2, s3, h, idx)
    if (s0, s1) == TARGET_1 and (s2, s3) == TARGET_2 and h == TARGET_H:
        print(sched)
        break
```

Schedule unik: **`2 0 4 1 3 0 2 4`**. Jalur sukses lalu membaca tabel terenkripsi 36-byte di `.rodata:0x2040` dan menggabungkannya dengan word state final, nilai history per-langkah, dan token input untuk mencetak flag byte demi byte.

```
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

## Catatan / Insight

**Pelajaran:** binary stripped tetap membocorkan bentuk-input lewat import table saja. Ketika target perbandingan akhir (empat word state + hash) sudah dipanggang di `.rodata` dan ruang pencariannya kecil (390.625 kombinasi), simulator eksaustif mengalahkan dynamic instrumentation atau SMT solving apa pun.

## Flag

```
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```
