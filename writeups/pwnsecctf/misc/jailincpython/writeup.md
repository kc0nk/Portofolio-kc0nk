# jailincpython

> **Event:** PwnSec CTF 2026  
> **Kategori:** Misc  
> **Kesulitan:** Medium  
> **Status:** Solved

## 1. Gambaran Challenge

Challenge merupakan Python jail dengan filter karakter yang terlihat ketat. Target akhirnya adalah memperoleh primitive eksekusi perintah tanpa menggunakan sintaks Python normal seperti pemanggilan fungsi dengan tanda kurung.

## 2. Kondisi Filter

Source challenge menerapkan beberapa pembatas utama:

- input ASCII maksimal 800 byte;
- karakter quote dilarang;
- digit dilarang;
- tanda kurung `(` dan `)` dilarang;
- jumlah titik `.` dibatasi maksimal 2.

Namun filter masih mengizinkan assignment target pada comprehension. Ini membuka bentuk seperti assignment terhadap `hint_A.__class_getitem__`.

## 3. Primitive `__class_getitem__`

Python memungkinkan ekspresi subscription:

```python
hint_A[x]
```

untuk memanggil `__class_getitem__`. Jika atribut tersebut diganti, subscription dapat dijadikan primitive pemanggilan fungsi tanpa menulis `(...)`. Ini menjadi inti bypass jail.

Payload memanfaatkan `lambda x:x.__getattribute__` untuk mendapatkan descriptor `object.__getattribute__`, kemudian menggunakan binding `__get__` agar dapat membuat attribute getter secara dinamis.

## 4. Merakit Nama Tanpa Quote dan Digit

Karena quote dan digit dilarang, nama-nama penting tidak ditulis sebagai string literal biasa. Source challenge menyediakan `hint_B` yang bernilai:

```text
%jailincpython
```

Selain itu repr bound method digunakan dan dipotong dengan slicing untuk membangun nama atribut yang diperlukan. Teknik ini menghasilkan string seperti:

```text
__class__
__dict__
__subclasses__
register
__builtins__
__import__
os
system
sh
```

## 5. Mencapai `__builtins__`

Dari dictionary milik `type`, `__subclasses__` dapat digunakan untuk menemukan `ABCMeta`. Fungsi Python `ABCMeta.register` mempunyai akses terhadap dictionary builtins normal. Dengan jalur descriptor dan attribute getter yang telah dibangun, payload akhirnya dapat mencapai `__import__`, kemudian modul `os`, lalu `os.system`.

Secara konseptual alurnya:

```text
hint_A[...]
   ↓
__class_getitem__ sebagai call primitive
   ↓
object.__getattribute__ descriptor
   ↓
attribute getter
   ↓
ABCMeta.register
   ↓
__builtins__
   ↓
__import__('os')
   ↓
os.system('sh')
```

## 6. Mendapatkan Shell

Payload final berukuran 788 byte. Setelah dievaluasi, payload menjalankan:

```python
os.system("sh")
```

Dengan demikian input berikutnya pada koneksi remote tidak lagi diproses sebagai ekspresi Python jail, tetapi sebagai perintah shell.

## 7. Membaca Flag

`run.sh` pada service menulis flag ke file dengan nama acak:

```text
/${RAND}.txt
```

Kemudian environment variable `FLAG` dihapus. Karena nama file berubah setiap instance, solver tidak meng-hard-code nama tersebut. Setelah memperoleh shell, perintah yang digunakan adalah:

```bash
cat /*.txt
```

Glob root tersebut menemukan file flag yang dibuat service.

## 8. Reproduksi

Solver resmi membaca endpoint dari `instance.json`, melakukan koneksi TLS, mengirim payload jail, menunggu shell, lalu menjalankan `cat /*.txt`. Secara umum:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

## 9. Hasil

Flag yang tercatat pada source:

```text
pwnsec{974f89d15ad10e5c}
```

## 10. Pembelajaran

Filter karakter tidak cukup untuk mengamankan Python eval jail. Audit juga harus memperhatikan assignment target, special method yang dapat diganti, descriptor binding, serta objek Python yang masih menyediakan akses ke builtins. `__class_getitem__` sangat menarik karena mengubah syntax subscription menjadi primitive pemanggilan.
