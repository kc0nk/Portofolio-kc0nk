---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Misc"
challenge: "mind-blowers"
flag: "tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}"
teknik: "Pickle escape via __loader__ yang tidak ada di denylist find_class; opcode pickle manual untuk pivot ke os.popen"
sumber: "https://github.com/Abdelkad3r/tjctf-2026"
---

# mind-blowers — TJCTF 2026 (Misc)

## Deskripsi Singkat

Servis TCP yang men-decode base64 input, meng-unpickle-nya dengan `RestrictedUnpickler`, dan meng-echo hasilnya. Denylist-nya memblokir `eval`, `exec`, `open`, `system`, `getattr`, dan sejenisnya di `find_class`.

## Analisis & Eksploitasi

Jalan keluarnya: `__loader__` *tidak* ada di denylist, dan `__loader__.load_module("sys")` memberimu `sys.modules`, yang sudah berisi `os` karena `socket` (yang diimport servis saat startup) secara transitif mengimpornya. Rangkai lewat opcode pickle buatan tangan (`GLOBAL`, `TUPLE`, `REDUCE`, dengan memo `BINPUT`/`BINGET` untuk menghindari mengulang rantainya):

```
getattr(builtins, "__loader__")
  .load_module("sys")
  .modules["os"]
  .popen("cat /flag.txt")
  .read()
```

Karena `getattr` sendiri di-denylist berdasarkan nama, bangun rantainya dengan menyusun opcode yang tepat secara manual — kamu tidak pernah memanggil `find_class("builtins", "getattr")`; kamu hanya menerbitkan byte pickle yang diinterpretasikan setara oleh op `REDUCE` milik unpickler.

## Flag

```
tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}
```
