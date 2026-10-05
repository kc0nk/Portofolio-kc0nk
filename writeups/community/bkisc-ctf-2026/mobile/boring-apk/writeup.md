---
ctf: "BKISC CTF 2026"
kategori: "Mobile (Android Reverse)"
challenge: "Boring APK"
flag: "BKISC{4nd0rid_m4z3_s0lving}"
teknik: "Dekripsi asset AES-GCM dari binary NDK, jalankan .so standalone lewat qemu-aarch64, lalu pecahkan graph-walk 27 langkah dengan meet-in-the-middle"
sumber: "https://github.com/Abdelkad3r/bkisc-ctf-2026/tree/main/boring-apk"
---

# Boring APK — BKISC CTF 2026 (Mobile / Android Reverse)

**Info soal:** Hard, 250 poin, target Android (arm64-v8a).

## Deskripsi Singkat

Judul soal ini adalah umpan: Android memang "membosankan" sampai kamu sadar bahwa pengecekan flag sudah dipindahkan dari layer Java/Kotlin ke library native, asset yang dipakainya terenkripsi AES-GCM, dan pengecekan itu sendiri adalah graph-walk 27 langkah dengan tiga state word yang berjalan, di mana hanya nilai akhirnya yang dibandingkan oleh verifier. Tidak satu pun tahap ini sulit sendiri-sendiri — yang membuat soal ini menantang adalah menumpuknya jadi satu.

## Tahap 0 — Reconnaissance

Triase APK standar. Extract APK dengan `unzip` dan lihat apa yang menarik:

```
lib/arm64-v8a/libnative.so    ← melakukan pengecekan flag sesungguhnya
assets/*                      ← blob berentropi tinggi, jelas terenkripsi
classes.dex                   ← wrapper Java/Kotlin yang tipis
```

Decompile DEX dengan `jadx`. `MainActivity` memuat library native (`System.loadLibrary("native")`) dan memanggil method JNI yang menerima flag yang diketik user dan mengembalikan boolean. Sebelum sampai ke pengecekan native, Activity ini mendekripsi beberapa file asset dari `assets/` ke memori.

Jadi pekerjaannya terbagi rapi jadi tiga:

1. Ambil kunci dekripsi + skema dari bytecode dan dekripsi asset-nya.
2. Buat `libnative.so` bisa jalan standalone, tanpa harus menyalakan emulator Android setiap kali mencoba.
3. Reverse pengecekannya, buat solver.

## Tahap 1 — Mendekripsi Asset

Bytecode-nya memberikan parameter secara plaintext ke kita. Dekripsi asset memakai **AES-GCM** dengan:

- kunci 32-byte yang tertulis langsung sebagai literal `byte[]` di smali,
- AAD = ASCII `"bkisc01"`,
- layout per-blob: `nonce[12] || ciphertext || tag[16]`.

```python
from Crypto.Cipher import AES

KEY = bytes([...])   # 32 byte diambil dari smali
AAD = b"bkisc01"

for path in encrypted_files:
    blob = open(path, "rb").read()
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(AAD)
    pt = cipher.decrypt_and_verify(ct, tag)
    open(path + ".dec", "wb").write(pt)
```

Tag GCM tervalidasi bersih — kuncinya benar di percobaan pertama. Asset hasil dekripsi adalah tujuh lookup table tetap yang akan dipakai pengecekan flag:

| File | Ukuran | Peran |
|---|---|---|
| `table_a` | 16 byte | Mask XOR per-langkah, diindeks oleh `(node + i) & 0xf` |
| `table_b` | 32 byte | Mixer aditif per-node, diindeks oleh `node & 0x1f` |
| `table_c` | 16 byte | Mixer aditif untuk update state |
| `path_nodes` | 28 byte | Node graph yang dikunjungi tiap langkah |
| `required_moves` | 27 byte | Output yang diharapkan dari `maze_compute_move` per langkah |
| `checkpoint_nodes` | 6 byte | Enam node "checkpoint" |
| `checkpoint_tags` | 6 × `u32` | Tag XOR yang dicampur ke `s12` di setiap checkpoint |

Struktur ini sudah memberi sinyal jelas bahwa ini adalah graph-walk: 28 node (`path_nodes` panjang 28 = 27 transisi = 27 posisi karakter) dan tiga state word yang berjalan.

## Tahap 2 — Menjalankan libnative.so Secara Standalone

Daripada bolak-balik lewat ADB dan device fisik untuk setiap kandidat, seluruh solver dijalankan dengan **`libnative.so` di bawah `qemu-aarch64-static`** pada x86-64. Ada dua hambatan sebelum library ini bisa dipakai sebagai executable standalone.

### Hambatan A — Layout `basic_string` libc++ NDK

Fungsi pengecekan yang di-export menerima `std::__ndk1::basic_string<char>` secara by-value dan mengembalikan satu juga. `basic_string` milik libc++ NDK punya dua bentuk internal:

- **Short string** — small string optimization; datanya hidup inline di dalam struct.
- **Long string** — tiga pointer: `{capacity, size, data*}`.

Bit mana dari `capacity` yang membedakan dua mode ini tergantung pada konfigurasi build libc++ (`_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT`, `_LIBCPP_BIG_ENDIAN`, dll). Empat kandidat layout dicoba; yang cocok dengan binary ini disebut **Layout B**:

```cpp
struct NdkLongString {
    size_t cap;        // bit 0 diset => mode long
    size_t size;       // panjang, tanpa terminator
    const char* data;  // menunjuk ke buffer yang diakhiri 0
};
```

Sebuah runner C++ sederhana membangun struct ini di sekitar kandidat flag dan memanggil entry point yang di-export secara langsung.

> **Peringatan: `basic_string` NDK tidak portabel antar versi SDK.** libc++ yang dibawa Android NDK sudah beberapa kali mengubah layout `basic_string`-nya sepanjang NDK r18 → r25+. Kalau kamu me-reverse kode native Android, siapkan diri untuk mencoba beberapa kandidat layout, jangan asal asumsi — kalau salah pilih, byte ukuran akan terbaca sebagai pointer data, "string"-mu akan terlihat kosong, dan pengecekan gagal di setiap input.

### Hambatan B — Membuat Linker Mau Memuatnya

`libnative.so` berjalan baik-baik saja di Android, tapi loader Linux menolaknya karena dua alasan:

1. **Symbol version yang merujuk versi `liblog.so` dan `libc.so` yang tidak diekspos Linux.** Script kecil `strip_versions.py` menelusuri ELF, menghapus section `.gnu.version_r` dan `.gnu.version`, dan membersihkan dynamic tag `DT_VERSYM`, `DT_VERNEED`, dan `DT_VERNEEDNUM` yang sesuai.
2. **`DT_NEEDED` pada `liblog.so`** — spesifik Android, tidak ada padanannya di Linux. Pengecekan flag tidak pernah mencatat log apa pun, jadi `patchelf --remove-needed liblog.so libnative.so` aman dilakukan.

Lalu:

```bash
patchelf --set-interpreter /lib/ld-linux-aarch64.so.1 libnative.so
patchelf --remove-needed liblog.so libnative.so
```

Setelah itu, program runner bisa di-build, loader-nya senang, dan:

```
$ qemu-aarch64-static ./runner 'BKISC{test_test_test_test_}'
0
$ qemu-aarch64-static ./runner 'BKISC{4nd0rid_m4z3_s0lving}'
1
```

## Tahap 3 — Pengecekannya

Setelah melewati obfuskasi, pengecekan ini ternyata sebuah **graph-walk 27 langkah** dengan tiga state word 32-bit `s4`, `s8`, `s12`. Per langkah `i` (node saat ini `path_nodes[i]`, node berikutnya `path_nodes[i+1]`):

```c
uint8_t maze_compute_move(uint8_t ch, uint8_t node,
                          uint32_t s4, uint64_t i)
{
    uint8_t A   = table_a[(node + i) & 0xf];
    uint8_t B   = (s4 >> ((i & 3) * 8)) & 0xff;   // byte s4 dipilih oleh i
    uint8_t C   = table_b[node & 0x1f];
    uint8_t tmp = (ch ^ A) + B + C;
    return rotl8(tmp, 3) & 7;                      // 0..7
}
```

Karakter `ch` diterima di langkah `i` jika dan hanya jika `maze_compute_move(ch, ...) == required_moves[i]`. Ini filter per-langkah yang ketat — kebanyakan langkah hanya menyisakan 0–3 karakter valid dari 37 karakter alfabet `[a-z0-9_]`.

Setelah `ch` diterima, tiga state word ini di-update:

```c
new_s4  = (s4 * 0x83) ^ (uint32_t)(ch + table_c[(lookup + i) & 0xf] + i);

uint32_t v = (s8 ^ (lookup * 0x045d9f3bU)) ^ ((ch + i) * 0x9e37u);
new_s8  = rotl32(v, (ch & 7) + 1);

new_s12 = apply_checkpoint(s12, lookup, i);
```

`apply_checkpoint` hanya aktif ketika `lookup` (= `path_nodes[i+1]`) adalah salah satu dari enam node checkpoint; pada langkah-langkah itu, `rotl32(checkpoint_tag, i & 7)` di-XOR-kan ke `s12`. Enam checkpoint, enam tag.

Pengecekan lolos jika dan hanya jika setelah langkah ke-26:

```c
TARGET_S4  = 0xf9882dbc;
TARGET_S8  = 0xfd1a9600;
TARGET_S12 = 0x24f218ae;
```

State awal: `s4 = 0x762509d3`, `s8 = 0x4023cc45`, `s12 = 0`.

Posisi flag 0..5 sudah tetap (`BKISC{`) dan posisi 26 juga tetap (`}`). Itu menyisakan **21 posisi bebas** dari alfabet 37 karakter, artinya ruang pencarian `37²¹ ≈ 8.7 × 10³²` — mustahil kalau brute-force langsung.

## Tahap 4 — Meet-in-the-Middle

Dua observasi membuat masalah ini bisa dipecahkan:

1. Pengecekan per-langkah biasanya hanya menyisakan segelintir kandidat `ch` per posisi, jadi DFS biasa bisa banyak dipangkas. Tapi sendirian, itu tidak cukup cepat untuk 21 posisi bebas.
2. **Ketiga update state-nya bisa dibalik (invertible).**

Pisahkan walk-nya di langkah 13.

### Arah maju (forward)

DFS dari `i = 0` dengan `BKISC{` sudah dikonsumsi, sampai `i = 13`. Di setiap leaf:

- key = `(s4, s8, s12)` setelah langkah 13
- value = 7 karakter sufiks maju

Disimpan dalam hash map.

### Arah mundur (backward)

Balik update-nya mulai dari `(TARGET_S4, TARGET_S8, TARGET_S12)` di `i = 27`. Di setiap langkah mundur, enumerasikan 37 karakter alfabet; untuk setiap kandidat `ch`, hitung ulang state predecessor, cek constraint pengecekan per-langkah pada `i` yang didapat, lalu rekursi. Ketika sampai di `i = 13`, cari triple `(s4, s8, s12)` di map forward.

### Invers yang dibutuhkan

- **Update `s4` diakhiri dengan `* 0x83`.** Invers modular dari `0x83` mod `2³²` adalah `0xc9484e2b`. XOR bersifat self-inverse, jadi: kurangi `(ch + table_c[...] + i)` (di domain XOR), lalu kalikan dengan invers modularnya.
- **Update `s8` diakhiri dengan `rotl32(.., (ch & 7) + 1)`.** Begitu `ch` dienumerasikan, jumlah rotasi sudah diketahui, jadi un-rotate, lalu XOR balik dua mixer deterministiknya.
- **Update `s12` hanya meng-XOR konstanta pada langkah checkpoint.** XOR bersifat self-inverse — trivial.

```c
#define SPLIT     13
#define INV_M     0xc9484e2bu

// forward:  bangun map[(s4, s8, s12)] -> prefix
// backward: dari TARGET, mundur ke i = SPLIT lalu cari di map
```

## Eksploitasi / Solusi

```
$ ./solver --split 13 --target f9882dbc:fd1a9600:24f218ae
[forward]  4,365,856 entries built in 18.4 s
[backward] collision found at i=13 after 76.0 s
flag       BKISC{4nd0rid_m4z3_s0lving}
```

Proses backward menghasilkan tepat satu collision. Flag-nya menuntaskan lelucon di judul — Android bukan "membosankan"; ternyata "maze solving" (memecahkan labirin).

## Catatan / Pelajaran

1. **Tumpuk masalahnya; jangan diselesaikan sekaligus secara langsung.** Soal ini terlihat menakutkan karena terdiri dari tiga tahap terpisah, padahal masing-masing sederhana kalau berdiri sendiri. Kenali tahap-tahapnya lebih awal: extraction APK adalah pekerjaan plumbing, dekripsi asset adalah soal GCM, eksekusi native adalah soal patching loader, dan kriptografinya cuma sebuah state machine. Tidak ada satu pun yang setingkat riset.
2. **Menjalankan `.so` secara standalone lewat qemu jauh lebih cepat daripada instrumentasi Android apa pun.** Kalau library native soal tidak benar-benar bergantung pada framework Android (tidak pakai environment JNI, tidak pakai syscall khusus Bionic), hapus metadata versi, patch `DT_NEEDED` yang spesifik Android, dan jalankan langsung. Iterasi bisa 100× lebih cepat dibanding lewat Frida atau ADB.
3. **`basic_string` libc++ milik NDK adalah jebakan CTF yang berulang.** Kalau fungsi JNI menerimanya secara by-value, kamu harus mereproduksi layout ABI yang persis di runner-mu. Jangan asal asumsi — enumerasikan empat varian kanonik (short/long × normal/alternate) dan pilih yang menghasilkan jawaban masuk akal.
4. **Meet-in-the-middle sangat berguna kapan pun transisi state-nya invertible.** `(s_{i+1}) = f(s_i, ch_i)` menjadi `(s_i) = f⁻¹(s_{i+1}, ch_i)` adalah inti permainannya. Menyadari bahwa mixer di soal ini — perkalian modular, XOR, rotasi — semuanya invertible adalah insight kuncinya. Kompleksitas kerja jadi akar kuadrat dengan tukar tempat pakai memori hash table.
5. **`a * b mod 2ⁿ` invertible jika dan hanya jika `b` ganjil.** `0x83` ganjil, jadi punya invers modular, dihitung dengan extended Euclidean algorithm. Trik yang sama bisa dipakai untuk membalik kebanyakan mixer bergaya LCG di CTF.

## Flag

```
BKISC{4nd0rid_m4z3_s0lving}
```
