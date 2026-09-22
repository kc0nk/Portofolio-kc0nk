# Writeup CTF — logic

> **Kategori:** Cryptography / Miscellaneous Logic  
> **Target:** `nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30010`  
> **Format Flag:** `CYBERLEAGUE{...}`

---

## 1. Deskripsi Challenge

Challenge ini berjudul **logic** dengan deskripsi:

```text
Cant spell logic without some ls. Maybe Ls too.
```

Server menerima sebuah string lalu mengevaluasi sebuah ekspresi `assert` yang sangat panjang. Ketika input tidak memenuhi kondisi tersebut, server memperlihatkan traceback Python beserta ekspresi logika yang digunakan.

Contoh interaksi:

```text
[kconk@192 Downloads]$ nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30010
>> aaaa
Traceback (most recent call last):
  File "/app/logic.py", line 3, in <module>
    assert ogic(...)
    ...
    IndexError: string index out of range
```

Hal yang sangat menarik adalah traceback membocorkan hampir seluruh **circuit boolean** yang digunakan untuk memvalidasi flag. Dengan kata lain, program tidak memberikan ciphertext yang harus didekripsi, melainkan memberikan formula logika yang harus dipenuhi.

---

## 2. Observasi Awal

Ada beberapa petunjuk penting dari deskripsi dan traceback.

### 2.1. Petunjuk `ls` dan `Ls`

Deskripsi:

```text
Cant spell logic without some ls. Maybe Ls too.
```

memberikan indikasi kuat bahwa karakter yang digunakan di dalam flag akan berhubungan dengan:

```text
l
L
```

Setelah melihat kondisi akhir pada traceback:

```python
all(i in 'Ll' for i in lL[12:-1])
```

petunjuk tersebut menjadi jelas.

Artinya, bagian isi flag setelah prefix hanya boleh menggunakan:

```text
l
L
```

---

## 3. Identifikasi Fungsi `ogic`

Dari source yang bocor, fungsi utama adalah:

```python
ogic = lambda x, y=-1: not (x & (y if y>-1 else x))
```

Fungsi ini memiliki dua perilaku.

### 3.1. Satu argumen

Jika dipanggil:

```python
ogic(x)
```

maka karena `y = -1`, ekspresi menjadi:

```python
not (x & x)
```

Karena:

```text
x & x = x
```

maka:

```text
ogic(x) = not x
```

Jadi, pemanggilan satu argumen adalah **NOT**.

Secara matematis:

\[
ogic(x)=\neg x
\]

---

### 3.2. Dua argumen

Jika dipanggil:

```python
ogic(x, y)
```

maka ekspresi menjadi:

```python
not (x & y)
```

Ini adalah:

\[
ogic(x,y)=\neg(x \land y)
\]

atau **NAND**.

---

## 4. Mengapa NAND Penting?

NAND merupakan **functionally complete logic gate**.

Dengan NAND saja kita dapat membangun:

- NOT
- AND
- OR
- XOR
- dan fungsi boolean kompleks lainnya.

Contoh NOT:

```text
NOT(x) = NAND(x, x)
```

Pada challenge ini panitia membangun sebuah formula boolean yang sangat besar dengan ratusan operasi:

```python
ogic(...)
```

yang disusun secara bertingkat.

Jadi problem sebenarnya adalah:

> **Temukan assignment `True/False` untuk setiap karakter `lL[i]` sehingga root expression bernilai `True`.**

---

# 5. Struktur Flag

Dari kondisi yang terlihat di traceback:

```python
len(lL) == 78
```

dan:

```python
lL.startswith('CYBERLEAGUE{')
```

serta:

```python
lL.endswith('}')
```

maka struktur flag adalah:

```text
CYBERLEAGUE{
<65 karakter l/L>
}
```

Prefix:

```text
CYBERLEAGUE{
```

memiliki panjang:

```text
12
```

Suffix:

```text
}
```

memiliki panjang:

```text
1
```

Dengan total:

```text
12 + 65 + 1 = 78
```

Sehingga variabel yang dikontrol circuit adalah:

```text
lL[12] ... lL[76]
```

Jumlahnya:

```text
76 - 12 + 1 = 65
```

karakter.

---

# 6. Bentuk Validasi

Bagian akhir validasi mengandung kondisi seperti:

```python
ogic(
    ogic(...),
    ogic(
        ogic(
            ogic(
                lL.endswith('}'),
                ogic(
                    ogic(
                        len(lL) == 78,
                        1
                    ),
                    ogic(
                        lL.startswith('CYBERLEAGUE{'),
                        1
                    )
                )
            )
        )
    )
)
```

dan:

```python
all(i in 'Ll' for i in lL[12:-1])
```

Artinya terdapat dua kelompok validasi:

### Format flag

Harus:

```text
CYBERLEAGUE{...}
```

dengan panjang:

```text
78
```

### Karakter payload

Semua karakter dari:

```text
index 12 sampai 76
```

harus termasuk:

```text
'l'
'L'
```

---

# 7. Kesalahan Pendekatan Brute Force

Ada 65 posisi yang masing-masing mempunyai dua kemungkinan:

```text
l
L
```

Jika dilakukan brute force naif, ruang pencariannya adalah:

\[
2^{65}
\]

Nilai ini sangat besar.

```text
2^65 ≈ 3.69 × 10^19
```

Jadi jelas bukan pendekatan yang dimaksud challenge.

Kita harus memanfaatkan struktur circuit yang sudah dibocorkan.

---

# 8. Mengubah `logic.py` menjadi AST

Python memiliki modul built-in:

```python
ast
```

yang dapat dipakai untuk mem-parse source code menjadi **Abstract Syntax Tree**.

Tujuan kita adalah mengambil node:

```python
assert ...
```

dari:

```text
logic.py
```

lalu mengubah setiap operasi:

```python
ogic(x)
```

menjadi:

```text
NOT(x)
```

dan:

```python
ogic(x, y)
```

menjadi:

```text
NAND(x, y)
```

Dengan demikian source code yang awalnya sangat sulit dibaca dapat diubah menjadi struktur circuit yang jauh lebih teratur.

---

# 9. Representasi Node

Kita bisa membuat empat jenis node:

```python
class Var:
    def __init__(self, idx):
        self.idx = idx


class Const:
    def __init__(self, val):
        self.val = val


class Not:
    def __init__(self, a):
        self.a = a


class Nand:
    def __init__(self, a, b):
        self.a = a
        self.b = b
```

Interpretasinya:

```text
Var   -> variabel lL[index]
Const -> nilai boolean tetap
Not   -> NOT
Nand  -> NAND
```

---

# 10. Parsing AST

Fungsi `build()` digunakan untuk mengubah AST Python menjadi circuit internal.

```python
def build(node):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == 'ogic':
            args = [build(a) for a in node.args]

            if len(args) == 1:
                return Not(args[0])

            return Nand(args[0], args[1])

        # Fungsi format seperti startswith(), endswith(),
        # dan all() diperlakukan sebagai konstanta.
        return Const(True)

    elif isinstance(node, ast.Compare):
        left = node.left

        if isinstance(left, ast.Subscript):
            idx = left.slice

            if isinstance(idx, ast.Constant):
                i = idx.value
            else:
                i = ast.literal_eval(idx)

            return Var(i)

        return Const(True)

    elif isinstance(node, ast.Constant):
        return Const(bool(node.value))

    return Const(True)
```

Kemudian kita cari node `assert`:

```python
def parse_logic_source(path):
    src = open(path).read()

    tree = ast.parse(src)

    assert_node = next(
        n for n in tree.body
        if isinstance(n, ast.Assert)
    )

    return build(assert_node.test)
```

---

# 11. Mengapa Tidak `eval()`?

Sebaiknya jangan menjalankan formula langsung dengan:

```python
eval()
```

karena formula memiliki nesting yang sangat dalam.

Efeknya bisa berupa:

```text
RecursionError
```

atau eksekusi source yang sebenarnya tidak perlu dilakukan.

Pendekatan yang lebih aman dan lebih tepat untuk reversing challenge adalah:

```text
Source Code
    ↓
AST
    ↓
Circuit
    ↓
Backward Solving
    ↓
Flag
```

---

# 12. Backward Propagation

Setelah formula berhasil diubah menjadi circuit, kita tidak perlu mencoba semua kemungkinan.

Root dari `assert` harus bernilai:

```text
True
```

Maka kita dapat melakukan **propagasi dari root menuju leaf**.

---

## 12.1. NOT

Untuk:

```text
NOT(a) = target
```

maka:

```text
a = NOT(target)
```

Contoh:

```text
NOT(a) = True
```

berarti:

```text
a = False
```

Sebaliknya:

```text
NOT(a) = False
```

berarti:

```text
a = True
```

---

# 13. NAND

Definisi:

\[
NAND(a,b)=\neg(a\land b)
\]

Ada dua kasus.

### NAND harus bernilai False

Jika:

```text
NAND(a,b) = False
```

maka:

```text
a AND b = True
```

sehingga **keduanya harus True**:

```text
a = True
b = True
```

---

### NAND harus bernilai True

Jika:

```text
NAND(a,b) = True
```

maka:

```text
a AND b = False
```

Artinya minimal salah satu harus `False`.

Kita dapat memilih salah satu cabang untuk dipaksa `False`, sementara cabang lain dapat diberikan nilai yang kompatibel.

Dalam challenge ini struktur formula bersifat **read-once** untuk variabel yang digunakan, sehingga tidak muncul konflik assignment saat melakukan propagation.

---

# 14. Solver Backward

Implementasi:

```python
def solve(formula, assignment=None):
    assignment = {} if assignment is None else assignment

    def satisfy(node, desired):
        if isinstance(node, Var):
            if node.idx in assignment:
                if assignment[node.idx] != desired:
                    raise ValueError(
                        f"Konflik pada variabel index {node.idx}"
                    )

            assignment[node.idx] = desired

        elif isinstance(node, Const):
            if node.val != desired:
                raise ValueError(
                    "Konstanta tidak cocok"
                )

        elif isinstance(node, Not):
            satisfy(
                node.a,
                not desired
            )

        elif isinstance(node, Nand):

            if desired:
                # NAND(a,b)=True
                # cukup salah satu false
                satisfy(node.a, False)

                try:
                    satisfy(node.b, True)
                except ValueError:
                    satisfy(node.b, False)

            else:
                # NAND(a,b)=False
                # keduanya harus true
                satisfy(node.a, True)
                satisfy(node.b, True)

        else:
            raise TypeError(type(node))

    satisfy(formula, True)

    return assignment
```

---

# 15. Mengubah Assignment menjadi Karakter

Kita menyimpan hasil solving sebagai:

```python
assignment[index] = True
```

atau:

```python
assignment[index] = False
```

Kemudian konversi:

```text
True  -> 'l'
False -> 'L'
```

Kenapa?

Karena challenge sendiri memberi batas:

```python
all(i in 'Ll' for i in lL[12:-1])
```

Implementasi:

```python
def build_flag(
    assignment,
    total_len=78,
    prefix="CYBERLEAGUE{",
    suffix="}"
):
    chars = list(prefix)

    for i in range(
        len(prefix),
        total_len - len(suffix)
    ):
        chars.append(
            'l'
            if assignment.get(i, False)
            else 'L'
        )

    chars += list(suffix)

    return ''.join(chars)
```

---

# 16. Solver Lengkap

Berikut solver yang digunakan untuk memproses `logic.py` dan mengirim hasilnya ke service.

> **Catatan:** baris `pywn_placeholder` pada snapshot percakapan merupakan artefak. Tidak diperlukan. Solver di bawah menggunakan `pwntools` apabila tersedia dan memiliki fallback ke `socket`.

```python
#!/usr/bin/env python3

import ast
import socket
import sys


# ============================================================
# Circuit Nodes
# ============================================================

class Var:
    def __init__(self, idx):
        self.idx = idx


class Const:
    def __init__(self, val):
        self.val = val


class Not:
    def __init__(self, a):
        self.a = a


class Nand:
    def __init__(self, a, b):
        self.a = a
        self.b = b


# ============================================================
# AST -> Circuit
# ============================================================

def build(node):
    if isinstance(node, ast.Call):

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "ogic"
        ):
            args = [
                build(a)
                for a in node.args
            ]

            if len(args) == 1:
                return Not(args[0])

            return Nand(
                args[0],
                args[1]
            )

        # startswith(), endswith(), all(), dll.
        # akan dipastikan benar oleh flag valid.
        return Const(True)

    elif isinstance(node, ast.Compare):

        left = node.left

        if isinstance(left, ast.Subscript):

            idx = left.slice

            if isinstance(idx, ast.Constant):
                i = idx.value
            else:
                i = ast.literal_eval(idx)

            return Var(i)

        return Const(True)

    elif isinstance(node, ast.Constant):
        return Const(
            bool(node.value)
        )

    return Const(True)


def parse_logic_source(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        src = f.read()

    tree = ast.parse(src)

    assert_node = next(
        n
        for n in tree.body
        if isinstance(n, ast.Assert)
    )

    return build(
        assert_node.test
    )


# ============================================================
# Backward Solver
# ============================================================

def solve(
    formula,
    assignment=None
):
    assignment = (
        {}
        if assignment is None
        else assignment
    )

    def satisfy(node, desired):

        if isinstance(node, Var):

            if node.idx in assignment:

                if (
                    assignment[node.idx]
                    != desired
                ):
                    raise ValueError(
                        f"Konflik pada "
                        f"variabel {node.idx}"
                    )

            assignment[node.idx] = desired

        elif isinstance(node, Const):

            if node.val != desired:
                raise ValueError(
                    "Circuit tidak satisfiable"
                )

        elif isinstance(node, Not):

            satisfy(
                node.a,
                not desired
            )

        elif isinstance(node, Nand):

            if desired:
                # NAND(a,b)=True
                # minimal salah satu false

                satisfy(
                    node.a,
                    False
                )

                try:
                    satisfy(
                        node.b,
                        True
                    )

                except ValueError:
                    satisfy(
                        node.b,
                        False
                    )

            else:
                # NAND(a,b)=False
                # keduanya harus true

                satisfy(
                    node.a,
                    True
                )

                satisfy(
                    node.b,
                    True
                )

        else:
            raise TypeError(
                type(node)
            )

    # assert harus True
    satisfy(
        formula,
        True
    )

    return assignment


# ============================================================
# Build Flag
# ============================================================

def build_flag(
    assignment,
    total_len=78,
    prefix="CYBERLEAGUE{",
    suffix="}"
):

    chars = list(prefix)

    for i in range(
        len(prefix),
        total_len - len(suffix)
    ):
        chars.append(
            "l"
            if assignment.get(i, False)
            else "L"
        )

    chars += list(suffix)

    return "".join(chars)


# ============================================================
# Submit
# ============================================================

HOST = (
    "cyberleague-shared-nlb-8eebe09f116ebe55"
    ".elb.ap-southeast-1.amazonaws.com"
)

PORT = 30010


def submit_pwntools(flag):

    from pwn import remote

    io = remote(
        HOST,
        PORT
    )

    io.recvuntil(
        b">> "
    )

    io.sendline(
        flag.encode()
    )

    print(
        io.recvall(
            timeout=3
        ).decode(
            errors="replace"
        )
    )


def submit_socket(flag):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.connect(
        (HOST, PORT)
    )

    banner = sock.recv(
        4096
    )

    print(
        banner.decode(
            errors="replace"
        ),
        end=""
    )

    sock.sendall(
        flag.encode()
        + b"\n"
    )

    response = sock.recv(
        4096
    )

    print(
        response.decode(
            errors="replace"
        )
    )

    sock.close()


# ============================================================
# Main
# ============================================================

def main():

    logic_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "logic.py"
    )

    print(
        "[*] Parsing logic.py ..."
    )

    formula = parse_logic_source(
        logic_path
    )

    print(
        "[*] Solving NAND circuit ..."
    )

    assignment = solve(
        formula
    )

    print(
        f"[+] Variables solved: "
        f"{len(assignment)}"
    )

    flag = build_flag(
        assignment
    )

    print()
    print(
        "[+] FLAG:"
    )
    print(
        flag
    )

    print()
    print(
        "[*] Submitting ..."
    )

    try:
        submit_pwntools(
            flag
        )
    except ImportError:
        submit_socket(
            flag
        )


if __name__ == "__main__":
    main()
```

---

# 17. Cara Menjalankan

Pastikan file challenge:

```text
logic.py
```

berada di direktori yang sama dengan solver.

Kemudian:

```bash
python3 solve.py
```

Jika menggunakan `pwntools`, install:

```bash
pip install pwntools
```

Namun secara teori solver sebenarnya hanya membutuhkan:

```text
Python 3
```

untuk bagian parsing dan solving, karena:

```python
ast
socket
sys
```

merupakan library standard.

---

# 18. Solving Tanpa Network

Karena server hanya digunakan untuk menerima flag akhir, solving dapat dilakukan sepenuhnya secara lokal.

Contoh:

```bash
python3 solve.py logic.py
```

Output solver:

```text
[*] Parsing logic.py ...
[*] Solving NAND circuit ...
[+] Variables solved: 65

[+] FLAG:
CYBERLEAGUE{llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL}
```

Flag tersebut kemudian dapat diverifikasi secara manual melalui:

```bash
nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30010
```

lalu:

```text
>> CYBERLEAGUE{llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL}
```

---

# 19. Hasil Verifikasi

Flag yang diperoleh dari penyelesaian circuit dan telah diverifikasi terhadap kondisi `assert` adalah:

```text
CYBERLEAGUE{llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL}
```

Struktur flag:

```text
CYBERLEAGUE{
llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL
}
```

Jumlah karakter:

```text
78
```

Prefix:

```text
CYBERLEAGUE{
```

Payload:

```text
65 karakter l/L
```

Suffix:

```text
}
```

Seluruh karakter payload memenuhi:

```python
all(i in 'Ll' for i in lL[12:-1])
```

dan circuit NAND menghasilkan:

```text
True
```

---

# 20. Kenapa Solusi Ini Efektif?

Challenge terlihat sangat rumit karena expression `assert` sengaja dibuat sebagai nesting `ogic(...)` yang sangat panjang.

Namun setelah dibedah:

```text
ogic(x)
    ↓
NOT(x)

ogic(x, y)
    ↓
NAND(x, y)
```

maka keseluruhan challenge hanyalah sebuah **boolean circuit**.

Kita tidak perlu:

- RSA
- AES
- XOR cryptanalysis
- brute force
- Z3
- Sage
- RsaCtfTool

Teknik yang diperlukan hanya:

```text
Source Code Analysis
        ↓
AST Parsing
        ↓
NAND Circuit Reconstruction
        ↓
Backward Boolean Propagation
        ↓
Flag Reconstruction
```

---

# 21. Root Cause / Weakness

Dari sudut pandang security challenge, kelemahan utamanya adalah **validator membocorkan formula validasi melalui traceback**.

Input yang salah:

```text
aaaa
```

menyebabkan:

```text
IndexError
```

dan traceback menampilkan ekspresi:

```python
assert ogic(...)
```

Sehingga attacker dapat:

1. memperoleh struktur validator;
2. memahami primitive `ogic`;
3. mengubah validator menjadi circuit;
4. menyelesaikan circuit secara statis;
5. menghasilkan flag tanpa brute force.

Dengan kata lain, program memberikan terlalu banyak informasi internal ketika terjadi error.

---

# 22. Lessons Learned

Beberapa teknik yang dapat dibawa ke challenge lain:

### 22.1. Jangan abaikan traceback

Pada CTF, traceback sering kali merupakan **source leak tidak langsung**.

Informasi seperti:

```text
/app/logic.py
line 3
assert ogic(...)
```

dapat menjadi petunjuk utama.

### 22.2. Identifikasi primitive terlebih dahulu

Sebelum mencoba brute force, cari tahu apa yang dilakukan fungsi pembantu.

Pada challenge ini:

```python
ogic
```

ternyata hanya:

```text
NOT
NAND
```

### 22.3. Gunakan struktur formula

Formula yang sangat panjang tidak selalu berarti masalah sulit.

Ketika variabel muncul satu kali atau circuit dapat ditelusuri secara deterministik, **backward propagation** sering jauh lebih sederhana daripada SAT solving.

### 22.4. Periksa clue dari deskripsi

Petunjuk:

```text
some ls
Maybe Ls too
```

selaras dengan validator:

```python
all(i in 'Ll' ...)
```

Deskripsi memang memberi clue tentang domain solusi.

---

# 23. Ringkasan Attack / Solve Chain

```text
Connect ke service
      │
      ▼
Masukkan input invalid
      │
      ▼
Traceback membocorkan assert
      │
      ▼
Temukan fungsi:
ogic(x)     = NOT(x)
ogic(x,y)   = NAND(x,y)
      │
      ▼
Parse logic.py menggunakan AST
      │
      ▼
Bangun boolean circuit
      │
      ▼
Root harus TRUE
      │
      ▼
Backward propagation
      │
      ▼
65 variabel l/L terpecahkan
      │
      ▼
Gabungkan dengan:
CYBERLEAGUE{ ... }
      │
      ▼
Submit flag
      │
      ▼
CYBERLEAGUE{llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL}
```

---

# 24. Flag

```text
CYBERLEAGUE{llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL}
```

---

## Referensi Percakapan

Source analisis:

```text
https://claude.ai/share/81ae4f31-cac3-4e25-97b5-aa56eea209e9
```

> Writeup ini disusun berdasarkan analisis dan hasil verifikasi yang terdapat pada shared conversation tersebut.
