---
ctf: "boroCTF 2026"
kategori: "Reverse Engineering"
challenge: "big_brother"
flag: "boroCTF{AHK_1s_lIs+eni4g}"
teknik: "PE hasil kompilasi AutoHotkey; script tertanam sebagai RCDATA dan memakai hotstring trigger yang di-concatenate lewat Chr()"
---

# big_brother — boroCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Sebuah executable GUI Windows berukuran ~914 KB. Perintah `file` mengenalinya sebagai `PE32 executable (GUI) Intel 80386`. Nama soal ("kakak besar") memberi petunjuk soal pengawasan/surveillance.

## Recon

`strings` saja sudah cukup untuk mengidentifikasi binary ini sebagai hasil kompilasi script AutoHotkey (AHK): ada manifest `<assembly>` yang menyebut AutoHotkey, import API seperti `RegisterHotKey`, `GetAsyncKeyState`, `MapVirtualKeyExW`, dan potongan teks polos dari script itu sendiri. Mode kompilasi AHK pada dasarnya "interpreter + script direkatkan jadi satu". Script-nya hidup sebagai `RCDATA` (resource type 10) di section `.rsrc` PE, dan tool seperti `wrestool -x -t10 big_brother` atau Resource Hacker bisa mengekstraknya dengan bersih. Di build ini, scriptnya begitu dekat dengan plaintext sehingga bahkan `strings` saja sudah memunculkan seluruh isinya.

**Script hasil ekstraksi:**

```ahk
:*:iloveboroctf::
secret := Chr(98) . Chr(111) . Chr(114) . Chr(111) . Chr(67) . Chr(84) . Chr(70) . Chr(123)
secret := secret . Chr(65) . Chr(72) . Chr(75) . Chr(95) . Chr(49) . Chr(115) . Chr(95)
secret := secret . Chr(108) . Chr(73) . Chr(115) . Chr(43) . Chr(101) . Chr(110) . Chr(105)
secret := secret . Chr(52) . Chr(103) . Chr(125)
MsgBox, 64, System Notification, Access Granted!`n`nFlag: %secret%
```

`:*:iloveboroctf::` adalah hotstring AHK dengan flag `*`. Trigger ini aktif begitu string literal `iloveboroctf` diketik di mana saja di sistem, tanpa perlu karakter akhir (end-character). Itulah tema "big brother"-nya: hook keyboard level-rendah milik AHK mengawasi setiap ketukan tombol untuk mencari trigger ini.

## Eksploitasi / Solusi

Flag adalah hasil obfuskasi berupa concatenation `Chr()` yang mengelabui `strings | grep boroCTF` yang naif, tapi tidak mengelabui reverser sungguhan. Cukup decode urutan `Chr()`-nya di Python:

```python
codes = [98,111,114,111,67,84,70,123,
         65,72,75,95,49,115,95,
         108,73,115,43,101,110,105,
         52,103,125]
print(''.join(chr(c) for c in codes))
# boroCTF{AHK_1s_lIs+eni4g}
```

Hasilnya terbaca sebagai "AHK is listening" (AHK sedang mendengarkan). Seorang reverser sungguhan juga punya opsi menjalankan binary di VM Windows lalu mengetik `iloveboroctf` di mana saja (Notepad pun bisa) untuk memicu MessageBox "Access Granted!" — tapi cara itu tidak diperlukan; cukup decode statis saja.

## Catatan / Insight

Flag bisa didapat sepenuhnya lewat analisis statis (tanpa menjalankan binary sama sekali). Ini sekali lagi menunjukkan pola umum di CTF ini: baca artefaknya (resource RCDATA yang mengandung script plaintext), bukan bungkusnya (executable Windows yang "terlihat rumit").

## Flag

```
boroCTF{AHK_1s_lIs+eni4g}
```
