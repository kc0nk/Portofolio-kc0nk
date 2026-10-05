---
ctf: "ASIS CTF Quals 2026"
kategori: "Web"
challenge: "2048"
flag: "ASIS{t0McAT_was_Th3_KEY}"
teknik: "Diagnostics JSP X-Forwarded-For spoof → Tomcat 9.0.116 CVE-2026-34486 (EncryptInterceptor meneruskan plaintext saat dekripsi gagal) → ysoserial CommonsCollections6 dibungkus frame Tribes FLT2002/TLF2003"
sumber: "https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Web/2048"
---

# 2048 — ASIS CTF Quals 2026 (Web, Hard)

## Deskripsi Singkat

Game 2048 yang terlihat hanyalah pengalih perhatian. Attack surface sungguhannya adalah Tribes receiver Apache Tomcat cluster di TCP 4000 yang `EncryptInterceptor`-nya membypass enkripsinya sendiri saat dekripsi gagal, membiarkan frame `ChannelData` plaintext tak-terautentikasi menjangkau `ObjectInputStream.readObject()` di baliknya.

## Analisis

**Recon.** `robots.txt` menyingkap `/citadel/lab-notes.html` yang mendeskripsikan seluruh arsitektur: gateway di TCP 4000, `AES/CBC/PKCS5Padding` untuk enkripsi pesan, "dekripsi gagal tidak menghentikan pemrosesan downstream", "library Commons Collections lama" di classpath, dua fragmen flag teracak di `/opt/citadel/vault` dan `/opt/citadel/gate`, file ditulis ke `/opt/citadel/shared` yang bisa didownload sekali lewat `/mirror.jsp?parcel=<label>`, dan konsol diagnostik yang digerbangi pengecekan header proxy.

**Konsol diagnostik.** `GET /diagnostics.jsp` mengembalikan 403. Konsol-nya menggerbangi berdasarkan IP client tapi mengambilnya dari `X-Forwarded-For` tanpa syarat, jadi loopback palsu berhasil:

```bash
curl -s -H 'X-Forwarded-For: 127.0.0.1' http://.../diagnostics.jsp | jq
```

Respons membocorkan: **Tomcat 9.0.116** (vulnerable), **Commons Collections 3.2.1** di classpath (gadget tersedia), dan **Tribes receiver di TCP 4000** yang memakai `AES/CBC/PKCS5Padding`.

**CVE-2026-34486 — plaintext fallthrough di `EncryptInterceptor`.** Jalur terima Tomcat 9.0.116 secara logis:

```java
try {
    data = encryptionManager.decrypt(data);
    replaceMessage(data);
} catch (GeneralSecurityException e) {
    log.error("Failed to decrypt message", e);
}
super.messageReceived(msg);
```

Panggilan `super.messageReceived(msg)` berada **setelah** try/catch, jadi kalau dekripsi gagal, `msg` tetap menyimpan plaintext asli attacker dan diteruskan ke sisa channel tanpa perubahan. **Kunci enkripsinya jadi tidak diperlukan** — mengirim ciphertext AES yang tidak valid dengan sengaja memicu exception, dan Tomcat lalu memproses byte asli sebagai frame plaintext.

**Merekonstruksi frame Tribes.** TCP 4000 tidak menerima stream serialisasi Java mentah. Receiver-nya mengharapkan frame transport `XByteBuffer` berisi struktur `ChannelData` ter-serialisasi: `"FLT2002" || uint32_be(panjang) || channel_data || "TLF2003"`. Dua field penting: **`source_member`** di-encode dalam format `MemberImpl` milik Tomcat (delimiter `TRIBES-B\x01\x00`/`TRIBES-E\x01\x00`); **`options` harus nol** — kalau bit `SEND_OPTIONS_BYTE_MESSAGE` diset, Tomcat membungkus body sebagai `ByteMessage`, tapi dengan bit itu kosong, `GroupChannel.messageReceived()` memanggil `XByteBuffer.deserialize()` pada body pesan, menjangkau `ObjectInputStream.readObject()` — sink deserialisasi Java klasik.

**Gadget Commons Collections 6.** `commons-collections-3.2.1.jar` di classpath membuka gadget chain Commons Collections klasik. Exploit-nya memakai payload `CommonsCollections6` milik ysoserial. Command remote-nya memakai wrapper `bash -c` brace-expansion tanpa-spasi untuk menghindari masalah tokenisasi `Runtime.exec(String)`: `bash -c {echo,<BASE64>}|{base64,-d}|{bash,-i}`. Script hasil decode-nya memilih dua file fragmen bernama-acak sambil mengecualikan umpan `README`/`flag.txt`, menulis gabungannya ke `/opt/citadel/shared` yang world-writable, dan endpoint mirror sekali-pakai mengembalikannya.

## Eksploitasi / Solusi

```text
[+] generated 1562-byte CommonsCollections6 payload
[+] sent 1697-byte Tribes frame to 91.107.164.78:4000
[+] fetching one-shot parcel asis_2048_<random>
[+] recovered: ASIS{t0McAT_was_Th3_KEY}
```

**Memisahkan flag dari umpan.** Listing direktori terproteksi setelah RCE menunjukkan `/opt/citadel/vault` berisi `README` (umpan), `flag.txt` (umpan: `ASIS{do_you_think_rick_sanchez_is_stupid?}`), dan `pf_9ba6bb1b7ff5.asc` (`ASIS{t0McAT_was`); `/opt/citadel/gate` berisi `launch_9d56e20cffbf.conf` (`_Th3_KEY}`). Label teracak-lah separuh kode peluncuran sungguhan; gabungkan urutan `vault` lalu `gate`.

```
ASIS{t0McAT_was_Th3_KEY}
```

## Catatan / Insight

Challenge ini menggabungkan tiga kegagalan trust independen:

- **Upgrade Tomcat melewati 9.0.116** supaya dekripsi gagal menghentikan pemrosesan pesan. Kalau exception handler milik komponen tetap meneruskan input yang gagal, itu bukan exception handler — itu bypass plaintext.
- **Jangan ekspos Tribes receiver ke jaringan tak-terpercaya.** Traffic membership dan transport cluster harus dibatasi ke peer terautentikasi di jaringan privat. `EncryptInterceptor` adalah ukuran defense-in-depth, bukan perimeter Internet publik.
- **Terima header forwarding hanya dari reverse proxy yang diketahui**, dan turunkan alamat client dari konfigurasi proxy terpercaya, bukan header request mentah. `X-Forwarded-For` dari client tak-terpercaya adalah kebohongan secara default.

Menghapus Commons Collections 3.2.1 juga menghapus gadget yang dipakai di sini, tapi tidak membuat deserialisasi Java tak-terautentikasi jadi aman — gadget berikutnya di classpath (atau objek dengan `readObject` yang tidak aman) hanya berjarak satu upgrade library.

## Flag

```
ASIS{t0McAT_was_Th3_KEY}
```
