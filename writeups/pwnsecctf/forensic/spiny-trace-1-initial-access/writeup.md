# Spiny Trace 1 - Initial Access

> **Event:** PwnSec CTF 2026  
> **Kategori:** Forensics  
> **Kesulitan:** Easy  
> **Status:** Partial / belum terverifikasi  
> **Format jawaban:** `T1234.001`

> ⚠️ **Spoiler:** Dokumen ini membahas analisis dan kandidat jawaban challenge.

## 1. Pendahuluan

Challenge meminta identifikasi sub-teknik MITRE ATT&CK yang menjelaskan bagaimana penyerang memperoleh eksekusi awal tanpa mengeksploitasi service dan tanpa mengirim attachment. Petunjuk terpenting adalah korban sendiri menjalankan kode karena mengira tindakan tersebut merupakan bagian dari verifikasi rutin.

## 2. Evidence

Satu-satunya input resmi yang tersedia adalah screenshot deskripsi challenge. Hash SHA-256 yang dicatat pada source adalah:

```text
a63bd7ab2a2fcbcf6dd70fbe65575bcf23dfebee323da9234c8713ad1fd21651
```

Screenshot menetapkan nama challenge `Spiny Trace 1 - Initial Access`, kategori Forensics, difficulty Easy, serta format jawaban `T1234.001`.

## 3. Analisis Perilaku

Evidence memberikan tiga karakteristik utama:

- tidak ada eksploitasi service;
- tidak ada attachment;
- korban menjalankan kode karena percaya bahwa langkah tersebut diperlukan untuk verifikasi.

Tidak adanya attachment membuat `T1204.002 - User Execution: Malicious File` tidak cocok. Fokusnya adalah tindakan pengguna yang menjalankan kode yang diberikan melalui skenario verifikasi.

## 4. Kandidat MITRE ATT&CK

Kandidat yang paling spesifik pada source adalah:

```text
T1204.004 - User Execution: Malicious Copy and Paste
```

Sub-teknik ini menggambarkan eksekusi yang terjadi setelah pengguna dipengaruhi secara sosial untuk menyalin dan menempelkan kode ke command interpreter. Source juga mengaitkannya dengan pola **ClickFix**, yaitu halaman error/CAPTCHA palsu yang mendorong pengguna menjalankan instruksi tertentu.

## 5. Membandingkan Kandidat

### T1204.001 - Malicious Link

Tidak menjadi kandidat utama karena bukti yang diberikan menekankan bahwa aksi penentu adalah **menjalankan kode**, bukan sekadar membuka link.

### T1204.002 - Malicious File

Tidak cocok karena source secara eksplisit menyatakan tidak ada attachment.

### T1204.004 - Malicious Copy and Paste

Cocok dengan seluruh petunjuk: korban diarahkan untuk melakukan tindakan verifikasi, kemudian menjalankan kode yang disediakan.

## 6. Masalah Format Submission

Source menyebut format jawaban seperti:

```text
T1234.001
```

Sementara placeholder platform berbentuk `pwnsec{...}`. Kandidat yang dicoba dengan wrapper:

```text
pwnsec{T1204.004}
```

**ditolak oleh platform**. Karena itu, source mempertahankan `T1204.004` sebagai kandidat raw sesuai format challenge.

## 7. Reproduksi Analisis

Tidak ada exploit atau solver kompleks yang diperlukan. Prosesnya adalah klasifikasi berbasis evidence:

```text
Baca skenario
    ↓
Catat exclusion: tidak ada service exploit
    ↓
Catat exclusion: tidak ada attachment
    ↓
Korban menjalankan kode
    ↓
Identifikasi keluarga User Execution
    ↓
Pilih sub-teknik Malicious Copy and Paste
    ↓
T1204.004
```

## 8. Hasil

Kandidat saat ini adalah:

```text
T1204.004
```

Namun statusnya **belum terverifikasi** karena source hanya mencatat bahwa `pwnsec{T1204.004}` ditolak. Tidak ada bukti pada source bahwa submission raw `T1204.004` telah diterima. Oleh sebab itu write-up ini tidak mengklaim flag terverifikasi.

## 9. Kesimpulan

Challenge menguji kemampuan memetakan perilaku korban ke sub-teknik MITRE ATT&CK secara spesifik. Perbedaan pentingnya adalah membedakan delivery channel dengan aksi yang menghasilkan eksekusi. Berdasarkan evidence yang tersedia, `T1204.004` merupakan kandidat yang didukung source, tetapi tetap berstatus **partial/unverified**.
