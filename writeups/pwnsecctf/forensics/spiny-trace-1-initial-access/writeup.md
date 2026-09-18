# Spiny Trace 1 - Initial Access

> **Kategori:** Forensics  
> **Kesulitan:** Easy  
> **Event:** PwnSec CTF 2026  
> **Status:** Partial / belum terverifikasi oleh platform  
> **Jenis jawaban:** MITRE ATT&CK Sub-technique  
> **Format yang diminta:** `T1234.001`

> ⚠️ **Spoiler:** Write-up ini membahas seluruh proses analisis dan kandidat jawaban.

---

## 1. Pendahuluan

**Spiny Trace 1 - Initial Access** adalah challenge kategori **Forensics** yang meminta kita mengidentifikasi teknik atau sub-teknik MITRE ATT&CK yang digunakan penyerang untuk memperoleh eksekusi awal pada komputer korban.

Petunjuk utama pada challenge menjelaskan bahwa:

- penyerang **tidak mengeksploitasi sebuah service**;
- penyerang **tidak mengirim attachment**;
- korban sendiri **menjalankan kode**;
- korban menjalankan kode tersebut karena mengira sedang melakukan **langkah verifikasi rutin**.

Dengan kata lain, fokus utama challenge bukan mencari exploit teknis pada service, melainkan mengidentifikasi **mekanisme social engineering yang menyebabkan pengguna mengeksekusi kode berbahaya**.

Berdasarkan karakteristik tersebut, teknik yang paling spesifik adalah:

```text
T1204.004 - User Execution: Malicious Copy and Paste
```

Namun, ada satu detail penting mengenai format submission yang perlu diperhatikan: kandidat yang dibungkus menjadi `pwnsec{T1204.004}` dilaporkan ditolak oleh platform. Challenge secara eksplisit meminta format seperti `T1234.001`, sehingga kandidat berikutnya adalah raw ID:

```text
T1204.004
```

Status akhir dalam source yang tersedia tetap **partial**, karena belum ada bukti bahwa platform menerima submission raw tersebut.

---

# 2. Informasi Challenge

| Properti | Nilai |
|---|---|
| Nama | `Spiny Trace 1 - Initial Access` |
| Event | PwnSec CTF 2026 |
| Kategori | Forensics |
| Difficulty | Easy |
| Format jawaban | `T1234.001` |
| Kandidat teknik | `T1204.004` |
| Status | Partial |

Challenge ini pada dasarnya merupakan **MITRE ATT&CK technique identification**.

Hal penting yang harus dilakukan adalah menerjemahkan deskripsi perilaku korban ke dalam terminologi ATT&CK.

---

# 3. Evidence

Evidence yang dipertahankan untuk challenge ini berasal dari screenshot deskripsi challenge.

Informasi file sumber yang tersedia:

```text
Source:
../challenge/codex-clipboard-693933eb-7841-4998-80ed-4c1a134a7b2c.png

SHA-256:
a63bd7ab2a2fcbcf6dd70fbe65575bcf23dfebee323da9234c8713ad1fd21651
```

Evidence memberikan tiga petunjuk yang sangat penting:

```text
1. Tidak ada eksploitasi service.
2. Tidak ada attachment.
3. Korban menjalankan kode karena mengira itu bagian dari proses verifikasi.
```

Ketiga poin tersebut cukup untuk mempersempit kemungkinan teknik ATT&CK secara signifikan.

---

# 4. Memahami Petunjuk "Initial Access"

Nama challenge mengandung:

```text
Initial Access
```

Dalam konteks MITRE ATT&CK, **Initial Access** merupakan tactic yang mencakup teknik yang digunakan adversary untuk memperoleh akses awal ke lingkungan target.

Pada challenge ini, kita tidak perlu mencari vulnerability seperti:

```text
RCE
SQL Injection
Buffer Overflow
Exploit Public-Facing Application
```

Alasannya adalah challenge secara eksplisit mengatakan bahwa **service tidak dieksploitasi**.

Hal tersebut berarti mekanisme memperoleh eksekusi berasal dari **interaksi pengguna**.

---

# 5. Petunjuk Pertama: Tidak Mengeksploitasi Service

Salah satu clue terpenting adalah:

```text
The attacker did not exploit a service
```

Artinya, skenario bukan seperti:

```text
Attacker
   |
   +--> exploit vulnerable web server
   |
   +--> exploit exposed service
   |
   +--> gain remote code execution
```

Jika service tidak dieksploitasi, kita harus mempertimbangkan mekanisme lain.

Kemudian challenge memberikan clue bahwa **korban sendiri menjalankan kode**.

Maka alurnya berubah menjadi:

```text
Attacker
   |
   +--> Social Engineering
           |
           v
        Victim
           |
           +--> executes supplied code
```

Ini merupakan indikator kuat bahwa teknik yang dicari berkaitan dengan **User Execution**.

---

# 6. Petunjuk Kedua: Tidak Ada Attachment

Challenge juga menyebutkan bahwa attacker:

```text
did not send an attachment
```

Ini penting karena MITRE ATT&CK memiliki sub-technique User Execution yang berkaitan dengan eksekusi file berbahaya.

Salah satu kandidat yang perlu dipertimbangkan adalah:

```text
T1204.002 - User Execution: Malicious File
```

Namun kandidat tersebut tidak sesuai.

Mengapa?

Karena challenge secara eksplisit mengatakan bahwa **tidak ada attachment**.

Dengan demikian:

```text
T1204.002
```

dapat kita eliminasi.

---

# 7. Petunjuk Ketiga: Korban Menjalankan Kode

Clue yang paling menentukan adalah korban:

> menjalankan kode karena mengira itu adalah langkah verifikasi rutin.

Ini berbeda dengan sekadar:

```text
victim clicks a link
```

atau:

```text
victim opens an attachment
```

Dalam skenario ini, tindakan yang menghasilkan eksekusi adalah:

```text
Victim
   |
   +--> copies/pastes supplied command or code
   |
   +--> command interpreter executes it
```

Dengan demikian, fokusnya adalah **malicious copy-and-paste execution**.

---

# 8. Kandidat MITRE ATT&CK

Teknik yang sesuai adalah:

```text
T1204.004
```

Nama lengkapnya:

```text
User Execution: Malicious Copy and Paste
```

Sub-technique ini berada di bawah:

```text
T1204 - User Execution
```

Secara konseptual:

```text
T1204
└── User Execution
    └── T1204.004
        └── Malicious Copy and Paste
```

Teknik ini menggambarkan situasi ketika attacker melakukan social engineering agar korban **menyalin dan menempelkan kode atau perintah** ke command interpreter, kemudian menjalankannya.

---

# 9. Mengapa T1204.004 Cocok?

Kita dapat mencocokkan setiap clue dengan karakteristik teknik.

| Clue Challenge | Interpretasi |
|---|---|
| Tidak mengeksploitasi service | Bukan service-side exploitation |
| Tidak ada attachment | Tidak cocok dengan malicious file |
| Korban menjalankan kode | User execution |
| Korban mengira sedang melakukan verifikasi | Social engineering |
| Kode dijalankan oleh korban | Execution bergantung pada tindakan user |
| Pola verifikasi/CAPTCHA palsu | Cocok dengan pola ClickFix |
| Diminta sub-technique `T1234.001` | Jawaban harus berupa ATT&CK sub-technique ID |

Kombinasi clue tersebut mengarah ke:

```text
T1204.004
```

---

# 10. ClickFix sebagai Petunjuk

Salah satu pola serangan yang relevan adalah **ClickFix**.

Secara umum, pola ini menggunakan halaman atau prompt palsu yang membuat korban percaya bahwa mereka perlu melakukan suatu tindakan untuk:

- menyelesaikan CAPTCHA;
- memperbaiki error;
- melakukan verifikasi;
- memvalidasi browser;
- atau menyelesaikan masalah teknis.

Korban kemudian diarahkan untuk melakukan tindakan yang sebenarnya berbahaya, misalnya menyalin dan menjalankan command.

Skema sederhananya:

```text
Korban membuka halaman
        |
        v
Muncul "Verification Required"
        |
        v
Korban percaya instruksi tersebut
        |
        v
Korban menyalin command
        |
        v
Korban menjalankan command
        |
        v
Malicious code dieksekusi
```

Inilah alasan clue:

```text
routine verification step
```

sangat penting.

Ia bukan sekadar informasi tambahan, tetapi merupakan indikator kuat dari pola **fake verification / ClickFix**.

---

# 11. Membandingkan Kandidat ATT&CK

Sebelum menetapkan jawaban, kita dapat membandingkan beberapa kandidat.

## 11.1 T1204.001 - Malicious Link

Sub-technique ini berkaitan dengan user execution melalui malicious link.

Namun challenge tidak menekankan bahwa korban cukup mengklik link sebagai tindakan eksekusi utama.

Yang ditekankan adalah:

```text
victim ran the code
```

Karena itu, `T1204.001` bukan mapping yang paling spesifik terhadap tindakan yang dijelaskan.

---

## 11.2 T1204.002 - Malicious File

Kandidat ini berkaitan dengan korban menjalankan file berbahaya.

Tetapi challenge secara eksplisit menyatakan:

```text
no attachment
```

Maka kandidat ini dapat dieliminasi.

```text
T1204.002
       X
       |
       +--> tidak ada malicious attachment/file
```

---

## 11.3 T1204.004 - Malicious Copy and Paste

Kandidat ini sesuai dengan skenario:

```text
Social engineering
       |
       v
Victim copies supplied command/code
       |
       v
Victim pastes into command interpreter
       |
       v
Code executes
```

Selain itu, pola fake verification/CAPTCHA merupakan indikasi yang konsisten dengan ClickFix.

Karena itu, ID yang paling sesuai dengan evidence adalah:

```text
T1204.004
```

---

# 12. Kenapa Bukan Sekadar "User Execution"?

Perlu diperhatikan bahwa:

```text
T1204
```

adalah parent technique.

Challenge meminta:

```text
T1234.001
```

yang menunjukkan bahwa kita harus memberikan **sub-technique**, bukan hanya parent technique.

Jadi:

```text
T1204
```

belum cukup spesifik.

Kita membutuhkan:

```text
T1204.004
```

---

# 13. Kesalahan Format Submission

Ada detail menarik pada proses validasi.

Kandidat pertama yang dilaporkan:

```text
pwnsec{T1204.004}
```

ternyata ditolak oleh platform.

Padahal placeholder pada screenshot menggunakan:

```text
pwnsec{...}
```

Hal ini dapat menimbulkan asumsi bahwa jawaban harus selalu dibungkus:

```text
pwnsec{...}
```

Namun challenge juga secara eksplisit memberikan format:

```text
T1234.001
```

Kedua informasi tersebut harus dibedakan.

### Format placeholder

```text
pwnsec{...}
```

belum tentu berarti wrapper tersebut adalah bagian dari jawaban.

### Format jawaban

```text
T1234.001
```

menunjukkan bahwa platform kemungkinan mengharapkan raw ATT&CK ID.

Oleh karena itu, kandidat submission yang direvisi adalah:

```text
T1204.004
```

---

# 14. Status Verifikasi

Berdasarkan evidence yang tersedia:

```text
pwnsec{T1204.004}
```

telah dilaporkan **ditolak** oleh platform.

Sedangkan:

```text
T1204.004
```

merupakan kandidat revisi berdasarkan format jawaban challenge.

Namun tidak tersedia bukti platform yang menunjukkan bahwa raw ID tersebut telah diterima.

Karena itu, status write-up ini sengaja tidak menyatakan bahwa flag sudah verified.

```text
Status:
PARTIAL

Candidate:
T1204.004

Verified:
Belum
```

Ini penting agar hasil analisis tidak mengklaim keberhasilan yang belum dibuktikan.

---

# 15. Alur Analisis Lengkap

Jika diringkas, proses solving dapat dibuat menjadi decision tree:

```text
                     Challenge
                         |
                         v
              Initial Access scenario
                         |
                         v
             Apakah service dieksploitasi?
                    /           \
                  Ya             Tidak
                  |               |
                exploit           v
                           Apakah ada attachment?
                              /          \
                            Ya            Tidak
                            |              |
                      malicious file       v
                                  Apakah user menjalankan
                                      supplied code?
                                            |
                                            v
                                  User Execution
                                            |
                                            v
                                  Copy / Paste code
                                            |
                                            v
                                      T1204.004
```

Versi yang lebih singkat:

```text
No service exploit
        +
No attachment
        +
Victim executes supplied code
        +
Fake verification / ClickFix pattern
        |
        v
T1204.004
```

---

# 16. Evidence Mapping

Berikut mapping evidence ke ATT&CK:

| Evidence | Kesimpulan |
|---|---|
| Attacker tidak mengeksploitasi service | Fokus berpindah dari exploitation ke user execution |
| Tidak ada attachment | `T1204.002` tidak sesuai |
| Korban menjalankan kode | Ada user-driven execution |
| Korban menganggapnya verifikasi rutin | Social engineering |
| Kode diberikan untuk dijalankan korban | Sesuai malicious copy/paste |
| Pola fake verification | Konsisten dengan ClickFix |
| Format `T1234.001` | Challenge meminta sub-technique ID |

Kesimpulan teknis:

```text
T1204.004 - User Execution: Malicious Copy and Paste
```

---

# 17. Apa yang Dipelajari dari Challenge Ini?

Challenge ini sederhana dari sisi tooling, tetapi menguji kemampuan membaca **behavioral evidence**.

Tidak ada kebutuhan untuk:

```text
Wireshark
Ghidra
IDA
Volatility
Binwalk
strings
GDB
pwntools
```

Solving lebih banyak bergantung pada:

1. memahami wording challenge;
2. mengidentifikasi tindakan yang menghasilkan execution;
3. memahami struktur MITRE ATT&CK;
4. mengeliminasi sub-technique yang tidak sesuai;
5. memperhatikan format submission.

Dalam forensics, tidak semua challenge membutuhkan analisis binary atau memory dump. Kadang-kadang informasi paling penting justru berada pada **konteks tindakan attacker dan korban**.

---

# 18. Kesalahan Umum yang Bisa Terjadi

## 18.1 Langsung menjawab T1204

Jawaban:

```text
T1204
```

terlalu umum jika challenge meminta sub-technique.

Kita harus menentukan sub-technique yang lebih spesifik.

---

## 18.2 Menganggap Semua User Execution adalah Malicious File

Tidak benar.

User Execution memiliki beberapa sub-technique. Dalam kasus ini tidak ada attachment/file yang dikirim.

Jadi:

```text
T1204.002
```

tidak sesuai dengan evidence.

---

## 18.3 Terjebak pada "Link"

Jika sebuah fake verification page dibuka melalui browser, seseorang mungkin langsung memilih:

```text
T1204.001
```

Tetapi delivery channel dan **aksi yang menyebabkan execution** harus dibedakan.

Jika decisive action adalah user menyalin dan menjalankan command, maka mapping yang lebih spesifik adalah malicious copy and paste.

---

## 18.4 Menganggap `pwnsec{...}` Pasti Wrapper

Placeholder:

```text
pwnsec{...}
```

tidak otomatis berarti seluruh submission harus menggunakan wrapper tersebut.

Dalam challenge ini, format eksplisit:

```text
T1234.001
```

lebih relevan untuk menentukan bentuk submission.

---

# 19. Reproduksi Analisis

Challenge ini tidak membutuhkan solver khusus.

Analisis dapat dilakukan secara manual.

Langkahnya:

### Langkah 1 — Baca skenario

Cari tindakan yang dilakukan korban.

```text
Victim ran the code.
```

### Langkah 2 — Catat exclusion

```text
No service exploitation.
No attachment.
```

### Langkah 3 — Identifikasi tactic/technique family

Karena execution bergantung pada tindakan user:

```text
User Execution
```

### Langkah 4 — Tentukan sub-technique

Karena mekanismenya adalah menjalankan kode yang diberikan melalui copy/paste:

```text
T1204.004
```

### Langkah 5 — Perhatikan format submission

Challenge meminta:

```text
T1234.001
```

Maka gunakan:

```text
T1204.004
```

bukan:

```text
pwnsec{T1204.004}
```

---

# 20. Reference

Referensi utama untuk mapping teknik:

**MITRE ATT&CK — User Execution: Malicious Copy and Paste**

```text
Technique ID:
T1204.004
```

Referensi resmi:

https://attack.mitre.org/techniques/T1204/004/

Halaman tersebut mendokumentasikan sub-technique **User Execution: Malicious Copy and Paste** dan konteks penggunaan social engineering untuk membuat pengguna menjalankan kode yang diberikan attacker.

---

# 21. Kesimpulan

Challenge **Spiny Trace 1 - Initial Access** dapat diselesaikan dengan melakukan behavioral mapping terhadap petunjuk yang diberikan.

Urutan reasoning-nya:

```text
Tidak ada service exploitation
            |
            v
Tidak ada attachment
            |
            v
Korban sendiri menjalankan kode
            |
            v
Eksekusi dipicu oleh social engineering
            |
            v
Pola fake verification / ClickFix
            |
            v
User Execution: Malicious Copy and Paste
            |
            v
T1204.004
```

Kandidat teknik yang diperoleh:

```text
T1204.004
```

Nama teknik:

```text
User Execution: Malicious Copy and Paste
```

Submission berikut:

```text
pwnsec{T1204.004}
```

telah dilaporkan ditolak oleh platform.

Berdasarkan format challenge:

```text
T1234.001
```

submission yang seharusnya diuji berikutnya adalah:

```text
T1204.004
```

Karena belum terdapat bukti acceptance dari platform dalam evidence yang tersedia, hasil akhir ditandai:

```text
PARTIAL / UNVERIFIED
```

---

# 22. Jawaban

### Kandidat final

```text
T1204.004
```

### Nama

```text
User Execution: Malicious Copy and Paste
```

### Status

```text
Belum terverifikasi oleh platform
```

---

## Ringkasan Singkat

| Item | Jawaban |
|---|---|
| MITRE ATT&CK | `T1204.004` |
| Technique | User Execution: Malicious Copy and Paste |
| Parent | `T1204 - User Execution` |
| Pola serangan | Social engineering / ClickFix |
| Attachment | Tidak ada |
| Service exploit | Tidak ada |
| User menjalankan kode | Ya |
| `pwnsec{T1204.004}` | Ditolak |
| `T1204.004` | Kandidat submission berikutnya |
| Verified | Belum |

> **Final candidate: `T1204.004`**
