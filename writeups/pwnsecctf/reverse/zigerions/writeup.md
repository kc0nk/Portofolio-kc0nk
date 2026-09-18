# Zigerions

## Informasi Challenge

| Item | Detail |
|---|---|
| Kategori | Reverse Engineering |
| Kesulitan | Hard |
| File awal | `public.zip` |
| Teknik utama | ELF → PyInstaller → PE → VMProtect → Game Boy ROM → hidden ELF → AES |
| Flag format | `psctf{...}` |

---

## 3.1 Gambaran Umum

`Zigerions` adalah challenge berlapis.

Rantai artifact-nya:

```text
public.zip
   │
   ▼
Linux ELF
   │
   ▼
embedded PE
   │
   ▼
Python 3.10 PyInstaller
   │
   ▼
obfuscated PE
   │
   ▼
VMProtect
   │
   ├───────────────┐
   ▼               ▼
Game Boy ROM    hidden ELF
   │               │
   │               ▼
   │             AES
   │               │
   ▼               ▼
decoy           flag
```

Bagian Game Boy terlihat seperti tujuan utama, tetapi sebenarnya berfungsi sebagai **decoy**.

---

## 3.2 ZIP

`public.zip` menggunakan password:

```text
infected
```

SHA-256 ZIP:

```text
39f883b263363a25d52f2227dca764bacf4fa5f4c534baab0d1701a232ebae83
```

File di dalam ZIP:

```text
Pickle_Riiiiick
```

berukuran sekitar:

```text
43 MB
```

dan merupakan static x86-64 ELF.

---

## 3.3 ELF Stage Pertama

ELF utama menulis PE ke:

```text
$HOME/.cache/.icons/.hidden/update.exe
```

PE tersebut merupakan PyInstaller stub Python 3.10.

Di dalam PE ditemukan marker:

```text
<<<PAYLOAD_START>>>
```

Setelah marker terdapat:

```text
4 byte payload length
payload terenkripsi/teracak
```

Payload length:

```text
0x555000
```

---

## 3.4 Membalik Obfuscation

Key XOR:

```text
A5 3C FF 00 55 AA
```

Operasi yang dilakukan:

```python
decoded = bytes(
    value ^ XOR_KEY[index % len(XOR_KEY)]
    for index, value in enumerate(scrambled)
)[::-1]
```

Jadi ada dua tahap:

```text
scrambled
   │
   ▼
XOR repeating key
   │
   ▼
reverse
   │
   ▼
PE
```

Validasi sederhana:

```python
decoded.startswith(b"MZ")
```

Jika benar, kita mendapatkan PE yang lebih dalam.

---

## 3.5 VMProtect

Recovered PE:

```text
final.exe
```

Ukuran:

```text
5,591,040 bytes
```

SHA-256:

```text
89a4f03151228ced4fbaf0ec4ff89bbf7895e25e67d55b8331e2e0543d3c8de7
```

Section seperti:

```text
.vmp0
.vmp1
```

dan entry point yang tidak biasa mengindikasikan VMProtect.

Mencoba membongkar seluruh VMProtect secara statis bukan jalur paling efisien.

Solusi yang digunakan adalah mengambil informasi dari proses setelah unpacking terjadi.

---

## 3.6 Frida dan ShellExecuteA

`final.exe` dijalankan menggunakan Frida.

Hook dipasang pada:

```text
ShellExecuteA
```

Tujuannya bukan menjalankan program normal, tetapi mengamati parameter yang akan dieksekusi.

Ditemukan:

```text
%TEMP%\AURA.gb
```

Artinya executable sedang menulis atau menjalankan Game Boy ROM.

---

## 3.7 Game Boy ROM

ROM berukuran:

```text
32 KiB
```

SHA-256:

```text
3141a477c0f440248e71146b2c6f4c582ef0a3a8db30a797df27d272e6812071
```

Setelah beberapa stage, ROM menampilkan:

```text
YOU GOT A
LITTLE GIFT ;)
```

Terdapat routine sekitar:

```text
0x15F2
```

yang memanggil:

```text
0x0AF2
```

tetapi fungsi tersebut segera melakukan:

```text
RET
```

Setelahnya terdapat sekitar 140 metadata opcode.

Ini tampak seperti VM kedua yang harus dianalisis.

Namun ternyata bukan payload utama.

---

## 3.8 Menemukan Hidden ELF

Pada saat yang sama, memory module utama masih menyimpan data lain.

Dari observasi runtime:

```text
base + 0x4000  → Game Boy ROM
base + 0xC000  → ukuran ROM = 0x8000
base + 0xC020  → hidden ELF
base + 0xD618  → ukuran hidden ELF = 0x15F8
```

Jadi hidden ELF dapat diambil langsung:

```python
size = base.add(0xd618).readU32()
blob = base.add(0xc020).readByteArray(size)
```

Ukuran:

```text
5624 bytes
```

SHA-256:

```text
eaccb6522ec941e1a00ad6360c26888de73da7316892e50b4ab752c81dc9e107
```

---

## 3.9 Mengapa Hidden ELF Lebih Penting?

Hidden ELF memiliki header:

```text
7F 45 4C 46
```

yaitu:

```text
ELF
```

Namun ELF tersebut tidak berisi program yang perlu dieksekusi.

Ia lebih mirip **data container**.

Bagian paling menarik terdapat pada:

```text
.rodata
.data
```

---

## 3.10 AES Key

16 byte pertama `.rodata`:

```text
M68K_AES_FLAGKEY
```

Panjangnya tepat:

```text
16 byte
```

sehingga cocok sebagai AES-128 key.

---

## 3.11 Ciphertext

`.data` berisi ciphertext sepanjang:

```text
48 byte
```

Hex:

```text
674e0e339bc75891878e9418bb3fb91a
f8fa389587016dfbe91db26b39b41c51
bc8a191fbdc5ad5fb30b22aa6c0d35b3
```

Karena:

```text
48 % 16 == 0
```

ciphertext cocok untuk AES block cipher.

---

## 3.12 AES-128-ECB

Gunakan:

```text
AES-128-ECB
```

dengan key:

```text
M68K_AES_FLAGKEY
```

Contoh:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

cipher = AES.new(
    b"M68K_AES_FLAGKEY",
    AES.MODE_ECB
)

plaintext = unpad(
    cipher.decrypt(ciphertext),
    AES.block_size
)
```

Padding yang ditemukan konsisten dengan:

```text
PKCS#7
```

Blok terakhir memiliki padding:

```text
09 09 09 09 09 09 09 09 09
```

---

## 3.13 Flag

Hasil dekripsi menghasilkan:

```text
psctf{U_sh0u1dvebeen_@_g@m3r_0rHighIQ!}
```

---

## 3.14 Solver End-to-End

Solver melakukan:

```text
1. Buka public.zip
2. Password = infected
3. Cari <<<PAYLOAD_START>>>
4. Baca payload length
5. XOR dengan repeating key
6. Reverse payload
7. Simpan final.exe
8. Spawn final.exe dengan Frida
9. Hook ShellExecuteA
10. Ambil hidden ELF dari memory
11. Parse ELF64 section table
12. Ambil .rodata
13. Ambil .data
14. Gunakan key AES
15. AES-128-ECB decrypt
16. PKCS#7 unpad
17. Validasi format flag
```

Jalankan:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

---

## 3.15 Teknik Frida yang Digunakan

Hook utama secara konsep:

```javascript
const shellExecute =
    Module.findGlobalExportByName('ShellExecuteA');

Interceptor.replace(
    shellExecute,
    new NativeCallback(function () {

        const base = Process.mainModule.base;
        const size = base.add(0xd618).readU32();

        const blob =
            base.add(0xc020).readByteArray(size);

        send({
            event: 'hidden-elf',
            size: size
        }, blob);

        return ptr(33);
    }, ...)
);
```

Return value:

```text
33
```

digunakan untuk membuat pemanggilan `ShellExecuteA` dianggap berhasil tanpa harus membuka aplikasi sebenarnya.

API message box juga diganti agar GUI tidak mengganggu proses otomatis.

---

## 3.16 Kenapa Tidak Perlu Membongkar VMProtect Sepenuhnya?

Ini salah satu poin terpenting.

VMProtect memang membuat static reverse engineering lebih sulit. Namun tujuan reverse engineering bukan selalu:

```text
"pahami semua kode"
```

Tujuan yang lebih tepat:

```text
"temukan jalur data yang menghasilkan flag"
```

Dalam challenge ini, runtime memory memberikan:

```text
hidden ELF
```

secara langsung.

Jadi:

```text
unpack → intercept → dump resource → decrypt
```

lebih sederhana daripada:

```text
unpack → defeat VMProtect → reverse semua VM → emulate seluruh program
```

---
