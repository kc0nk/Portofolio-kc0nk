# PHP Sandbox Escape

## 1.1. Informasi Challenge

| Properti | Nilai |
|---|---|
| Kategori | PWN |
| Kesulitan | Hard |
| Target | PHP 8.x / PHP-FPM |
| Flag format | `pwnsec{...}` |
| Teknik | Use-After-Free, heap spraying, arbitrary read, fake Closure |

Flag yang diperoleh:

```text
pwnsec{5dbe4132b1294725}
```

---

## 1.2. Gambaran Umum

Challenge ini menyediakan sandbox PHP yang membatasi banyak fungsi berbahaya.

Konfigurasi target antara lain menggunakan:

- `open_basedir`
- `disable_functions`
- PHP-FPM
- fungsi-fungsi filesystem dan process yang dibatasi
- `readflag` sebagai binary setuid root yang membaca `/flag`

Secara normal kita tidak bisa sekadar melakukan:

```php
system("cat /flag");
```

atau:

```php
unserialize($data);
```

karena fungsi-fungsi tersebut dibatasi.

Namun, pembatasan nama fungsi tidak berarti seluruh internal PHP yang berhubungan dengan fungsi tersebut hilang dari memory.

Kelemahan utama challenge berada pada interaksi antara:

```text
SplDoublyLinkedList::unserialize()
        ↓
Serializable::unserialize()
        ↓
rekursi parser serialization
        ↓
shared var_hash
        ↓
free HashTable
        ↓
dangling pointer
        ↓
Use-After-Free
```

UAF tersebut kemudian diperbesar menjadi arbitrary read dan akhirnya fake `zend_closure`.

---

## 1.3. Bug pada Shared `var_hash`

Payload exploit membuat object `stdClass` dengan delapan property.

Secara konseptual:

```php
O:8:"stdClass":8:{
    s:2:"p0";i:...;
    s:2:"p1";i:...;
    ...
    s:2:"p7";i:...;
}
```

Delapan property memenuhi HashTable sampai kapasitasnya.

Kemudian terdapat object:

```php
class CachedData implements Serializable {
    public function serialize(): string {
        return '';
    }

    public function unserialize(string $data): void {
        global $carrier;
        $carrier[0]->x = 0;
    }
}
```

Bagian penting adalah:

```php
$carrier[0]->x = 0;
```

Object pertama sebelumnya sudah mempunyai delapan property.

Menambahkan property ke-9:

```text
p0
p1
p2
p3
p4
p5
p6
p7
x       ← property baru
```

memaksa PHP melakukan resize HashTable.

---

## 1.4. Kenapa Resize Menghasilkan UAF?

HashTable lama berada pada allocation tertentu, misalnya:

```text
old arData
+----------------------------+
| zval p0                    |
| zval p1                    |
| ...                        |
| zval p7                    |
+----------------------------+
```

Ketika property ke-9 ditambahkan, PHP memperbesar table:

```text
old table  →  new table
```

dan buffer lama di-`free`.

Masalahnya adalah parser serialization masih mempunyai referensi melalui `var_hash` ke lokasi lama.

Akibatnya:

```text
var_hash
   │
   ├── R:3 → freed memory
   ├── R:4 → freed memory
   ├── ...
   └── R:10 → freed memory
```

Ini merupakan Use-After-Free.

---

## 1.5. Mengontrol Memory yang Sudah Di-free

Ukuran buffer lama sekitar 288 byte.

Exploit kemudian melakukan heap spraying menggunakan string sekitar 280 byte:

```php
$spray = str_repeat("\x00", 280);
```

Tujuannya adalah agar allocator menggunakan kembali chunk yang sebelumnya berisi property zval.

Dengan demikian memory yang sebelumnya ditafsirkan sebagai:

```text
zval
```

sekarang sebenarnya berisi:

```text
string data
```

Ketika parser menjalankan reference seperti:

```text
R:3
R:4
...
```

data string yang mengisi kembali chunk tersebut dapat ditafsirkan sebagai struktur internal PHP.

Inilah primitive awal untuk memory corruption.

---

## 1.6. Heap Leak

Solver pertama-tama membuat spray dengan pola khusus.

Contoh konsep:

```text
BBBB0000
BBBB0001
BBBB0002
...
```

Ketika chunk yang telah di-free dialokasikan kembali dan reference lama digunakan, perbedaan isi dapat diamati.

Fungsi:

```php
heap_leak()
```

mencari perubahan tersebut dan mengambil pointer yang berhasil terbaca.

Secara sederhana:

```text
freed chunk
     ↓
reallocated as sprayed string
     ↓
dangling zval digunakan
     ↓
string berisi pointer
     ↓
heap address leak
```

Heap leak ini penting karena exploit berikutnya harus menemukan object internal PHP di heap.

---

## 1.7. Menemukan `zend_object`

Setelah memperoleh alamat heap, exploit membuat banyak Closure:

```php
$GLOBALS["_spray_$i"] = function(){};
```

Sebanyak 256 object dibuat untuk mendapatkan pola memory yang berulang.

Kemudian sebuah string besar digunakan untuk membaca area heap.

Exploit mencari struktur yang menyerupai:

```text
zend_object
```

khususnya dua pointer penting:

```text
ce
handlers
```

Pada source solver terdapat offset:

```php
const OFF_OBJ_CE       = 0x10;
const OFF_OBJ_HANDLERS = 0x18;
```

Jadi bentuk sederhananya:

```text
zend_object
+0x00 ...
+0x10 ce
+0x18 handlers
```

Pointer tersebut digunakan untuk mengidentifikasi object PHP yang valid.

---

## 1.8. Menemukan `function_table`

Setelah mendapatkan alamat `handlers`, exploit mencari struktur executor globals di sekitar area tersebut.

Target berikutnya adalah:

```text
function_table
```

HashTable ini berisi fungsi internal PHP yang aktif.

Source exploit menggunakan struktur HashTable:

```text
nTableMask
arData
nNumUsed
```

dan kemudian mencari entry menggunakan hash Zend:

```text
DJBX33A
```

Implementasi hash:

```php
$h = 5381;

for (...) {
    $h = (($h << 5) + $h) + ord($key[$i]);
}
```

Ini memungkinkan solver mencari nama fungsi tertentu langsung dari memory.

---

## 1.9. Masalah `disable_functions`

Pada target, `system()` dinonaktifkan.

Namun:

```text
disable_functions
```

tidak berarti kode implementasi `system` hilang dari memory.

Entry asli masih dapat berada di static function table milik module standar.

Exploit memanfaatkan hubungan:

```text
function_table
     ↓
zend_internal_function
     ↓
module
     ↓
zend_function_entry[]
     ↓
zif_system
```

Dalam build target, ukuran entry:

```text
zend_function_entry = 0x38 bytes
```

Solver juga menggunakan index build-specific untuk menemukan entry `system`.

Ini merupakan bagian yang sangat bergantung pada versi/build PHP.

---

## 1.10. Membuat Fake Closure

Setelah address handler `system` diketahui, exploit membuat struktur yang menyerupai:

```text
zend_closure
```

dengan menggunakan pointer valid yang sebelumnya ditemukan dari Closure asli.

Secara konseptual:

```text
fake zend_closure
+-------------------------+
| valid zend_object       |
| valid handlers          |
| fake internal function  |
| handler = zif_system    |
+-------------------------+
```

Tujuannya adalah membuat PHP percaya bahwa object tertentu adalah Closure valid.

Primitive UAF kemudian digunakan untuk membuat memory tersebut terlihat sebagai:

```text
IS_OBJECT
```

dan saat dipanggil, kontrol berpindah ke:

```text
zif_system
```

---

## 1.11. Eksekusi `readflag`

Target memiliki binary:

```text
/readflag
```

yang mempunyai hak setuid root dan membaca `/flag`.

Karena exploit akhirnya memperoleh eksekusi melalui handler `system`, command yang dijalankan adalah:

```text
/readflag
```

Alur akhirnya:

```text
PHP UAF
   ↓
arbitrary read
   ↓
heap/object discovery
   ↓
function_table discovery
   ↓
system handler discovery
   ↓
fake zend_closure
   ↓
IS_OBJECT type confusion
   ↓
zif_system
   ↓
/readflag
   ↓
FLAG
```

---

## 1.12. Solver

Solver utama berada di:

```text
PHP Sandbox Escape/solve.py
```

Sedangkan exploit penelitian yang lebih mudah dibaca berada di:

```text
PHP Sandbox Escape/analysis/exploit.php
```

Jalankan:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

Solver melakukan:

1. koneksi HTTPS
2. pengiriman payload PHP
3. heap leak
4. UAF
5. arbitrary read
6. pencarian object internal
7. pencarian function table
8. resolusi `system`
9. fake Closure
10. ekstraksi flag

---

## 1.13. Flag

```text
pwnsec{5dbe4132b1294725}
```

---
