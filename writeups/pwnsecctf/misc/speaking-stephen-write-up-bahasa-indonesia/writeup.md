# Speaking Stephen — Write-up Bahasa Indonesia

> **PwnSec CTF 2026 — Misc**
>
> **Spoiler:** Dokumen ini berisi analisis lengkap dan flag.

---

## 1. Informasi Challenge

| Properti | Nilai |
|---|---|
| Nama | **Speaking Stephen** |
| Kategori | Misc |
| Kesulitan | Hard |
| Flag format | `PWNSEC{...}` |
| Target | Service transkripsi suara |
| Komponen utama | Whisper `tiny.en` + `espeak-ng` |
| Teknik | Audio adversarial example + SSML injection |
| Status | Solved |

### Flag

```text
PWNSEC{2B1BA663DDAEE8A5}
```

---

# 2. Gambaran Challenge

Deskripsi challenge sangat singkat:

```text
Can you make Stephen say what you want him to say?
```

Target menyediakan service yang menerima audio, melakukan:

```text
Audio
  ↓
Whisper
  ↓
Transcript
  ↓
espeak-ng -m
  ↓
Audio response
```

Pada pandangan pertama challenge terlihat seperti masalah speech-to-text biasa.

Namun ada sebuah **trust boundary yang salah**:

> Hasil transkripsi Whisper dianggap sebagai teks biasa, tetapi kemudian diberikan ke `espeak-ng` dalam mode markup/SSML.

Artinya, apabila kita dapat membuat Whisper menghasilkan karakter markup tertentu, output tersebut bukan lagi sekadar teks.

Contohnya:

```text
<audio src="flag.wav"/>
```

akan diproses sebagai elemen audio oleh eSpeak, bukan dibacakan sebagai teks.

Ini mengubah masalah menjadi:

```text
membuat Whisper mengeluarkan payload
        ↓
payload diperlakukan sebagai SSML
        ↓
SSML memuat flag.wav
        ↓
audio flag dikembalikan
        ↓
flag diekstrak dari audio
```

---

# 3. Analisis Arsitektur

Dari endpoint `/openapi.json` dan halaman utama, diketahui service mempunyai endpoint multipart:

```text
/transcribe
```

Model ASR yang digunakan:

```text
tiny.en
```

dan TTS menggunakan:

```text
espeak-ng
```

dengan mode:

```text
-m
```

Mode `-m` sangat penting karena membuat eSpeak menginterpretasikan input sebagai markup.

Secara sederhana:

```text
Whisper transcript
       │
       ▼
"hello world"
       │
       ▼
espeak-ng
       │
       ▼
audio normal
```

Tetapi jika transcript menjadi:

```text
<audio src="flag.wav"/>
```

maka alurnya berubah:

```text
Whisper transcript
       │
       ▼
<audio src="flag.wav"/>
       │
       ▼
espeak-ng -m
       │
       ▼
membaca file flag.wav
       │
       ▼
audio response
```

Inilah vulnerability utama challenge.

---

# 4. Mencari Sink Injection

## 4.1. Kenapa `espeak-ng -m` penting?

eSpeak NG mendukung markup/SSML.

Salah satu elemen yang menarik adalah:

```xml
<audio src="..."/>
```

Elemen tersebut memungkinkan eSpeak memasukkan audio eksternal ke hasil speech.

Karena challenge menyimpan:

```text
flag.wav
```

di direktori sound/icon server, target yang sangat menarik adalah:

```xml
<audio src="flag.wav"/>
```

Jika payload berhasil diproses, kita tidak perlu mengetahui flag secara langsung.

Kita hanya perlu memperoleh file audio yang berisi suara flag.

---

# 5. Masalah Utama: Whisper Tidak Mau Mengeluarkan Simbol

Mencoba membuat audio yang mengucapkan:

```text
<audio src="flag.wav"/>
```

tidak langsung berhasil.

Whisper mempunyai mekanisme `non_speech_tokens`.

Beberapa token yang dianggap sebagai simbol/non-speech ditekan selama decoding.

Karakter seperti:

```text
<
>
=
"
```

menjadi masalah karena karakter-karakter tersebut dibutuhkan untuk membentuk XML:

```xml
<audio src="flag.wav"/>
```

Jika kita hanya mengandalkan token individual untuk:

```text
<
>
=
"
```

Whisper cenderung menekan atau menghindarinya.

---

# 6. Insight Penting: Token Whisper adalah BPE

Whisper tidak bekerja dengan satu karakter = satu token.

Ia menggunakan tokenizer berbasis BPE.

Akibatnya, satu token dapat merepresentasikan gabungan beberapa karakter.

Contohnya, daripada memaksa Whisper menghasilkan:

```text
>
<
```

sebagai dua token simbol terpisah, kita dapat mencari token yang langsung menghasilkan:

```text
><
```

Demikian pula:

```text
."
```

atau:

```text
="/>
```

dapat direpresentasikan sebagai token gabungan.

Jadi larangan terhadap token simbol tertentu tidak sama dengan:

```text
"string ini tidak mungkin dihasilkan"
```

Ini merupakan inti bypass.

---

# 7. Target String

Payload akhir yang digunakan:

```text
 The HTML code."><audio src="flag.wav"/>
```

Bagian terpenting adalah:

```text
"><audio src="flag.wav"/>
```

Prefix:

```text
 The HTML code.
```

membantu membuat rangkaian audio lebih natural bagi model dan membantu optimisasi transcript.

Payload lengkap:

```text
 The HTML code."><audio src="flag.wav"/>
```

Setelah diproses Whisper, kita ingin memperoleh sequence token yang menghasilkan markup tersebut.

---

# 8. Token Sequence

Token penting pada `tiny.en` yang ditemukan adalah:

| Token ID | Representasi |
|---:|---|
| `526` | `."` |
| `6927` | `><` |
| `24051` | `audio` |
| `12351` | ` src` |
| `2625` | `="` |
| `32109` | `flag` |
| `13` | `.` |
| `45137` | `wav` |
| `26700` | `"/>` |

Rangkaian tersebut memungkinkan karakter yang biasanya sulit dibuat secara individual direpresentasikan sebagai token gabungan.

Secara konseptual:

```text
token individual:
<   >   =   "

        ↓ sulit

combined BPE:
><
."
="
"/>
```

---

# 9. Mengapa BPE Berhasil Melewati Suppression?

Ini adalah perbedaan penting antara:

```text
token-level filtering
```

dan:

```text
string-level filtering
```

Misalnya sistem melarang token:

```text
<
```

tetapi token:

```text
><
```

masih valid.

Decoder kemudian menghasilkan:

```text
><
```

yang mengandung karakter:

```text
>
<
```

Dengan demikian karakter yang dianggap "terlarang" tetap dapat muncul sebagai bagian dari token lain.

Jadi:

```text
non_speech_tokens
```

bukan sebuah filter terhadap byte/string akhir.

---

# 10. Membuat Audio Adversarial

Sekarang masalahnya berubah menjadi:

> Bagaimana membuat file WAV yang ketika dimasukkan ke `tiny.en` menghasilkan token sequence yang kita inginkan?

Ini merupakan masalah optimisasi.

Script:

```text
analysis/optimize_audio.py
```

digunakan untuk melakukan optimisasi audio.

---

# 11. Representasi Audio

Whisper menerima waveform dan mengubahnya menjadi:

```text
audio waveform
      ↓
log-mel spectrogram
      ↓
encoder
      ↓
decoder
      ↓
token probabilities
```

Kita tidak langsung mengoptimalkan teks.

Yang dioptimalkan adalah waveform agar decoder mempunyai probabilitas tinggi untuk memilih token target.

Secara konseptual:

```text
x = waveform

x
↓
Whisper encoder
↓
decoder logits
↓
P(token_i | token_0 ... token_i-1, x)
```

Target kita adalah memaksimalkan:

```text
P(t0, t1, ..., tn | x)
```

---

# 12. Teacher-Forced Cross Entropy

Optimisasi menggunakan target token sequence.

Misalkan target:

```text
[t0, t1, t2, ..., tn]
```

Loss dapat ditulis sebagai:

```math
L(x) = - \sum_i log P(t_i | t_<i, x)
```

Kemudian waveform diubah secara iteratif:

```text
x
↓
forward Whisper
↓
loss
↓
gradient
↓
update x
↓
forward lagi
```

Tujuan:

```text
minimize L(x)
```

atau ekuivalen dengan:

```text
maximize probabilitas token target
```

---

# 13. Mengapa Optimisasi Harus Memperhatikan WAV Nyata?

Ada jebakan penting.

Audio yang dioptimalkan di memory bisa berbeda dari audio setelah disimpan sebagai WAV.

Misalnya:

```text
float32 waveform
       ↓
quantization
       ↓
16-bit PCM WAV
       ↓
Whisper
```

Jika optimisasi hanya dilakukan terhadap float32 tanpa memperhitungkan quantization, hasilnya bisa bekerja di local tensor tetapi gagal setelah file benar-benar disimpan.

Karena itu `optimize_audio.py` memasukkan efek penyimpanan 16-bit dalam forward path.

Konsepnya:

```text
optimized waveform
        ↓
16-bit quantization
        ↓
decode kembali
        ↓
Whisper
```

Dengan demikian objective lebih dekat dengan kondisi remote sebenarnya.

---

# 14. Hasil Optimisasi

Hasil optimisasi dikemas ke dalam solver.

Pada:

```text
Speaking Stephen/solve.py
```

WAV tersebut disimpan sebagai:

```text
gzip
   ↓
base64
```

Tujuannya agar payload audio dapat ditanam langsung di script.

Secara umum:

```python
payload = base64.b64decode(PAYLOAD_B64)
audio = gzip.decompress(payload)
```

Kemudian audio dikirim ke endpoint challenge.

---

# 15. Mengirim Payload

Solver mengambil URL dari:

```text
instance.json
```

kemudian mengirim WAV ke:

```text
/transcribe
```

Alur:

```text
solve.py
   ↓
decode gzip/base64
   ↓
WAV payload
   ↓
POST /transcribe
   ↓
server Whisper
```

---

# 16. Apa yang Terjadi di Server?

Ketika audio diterima:

```text
WAV
 ↓
tiny.en
 ↓
transcript
```

Transcript yang kita targetkan adalah kira-kira:

```text
The HTML code."><audio src="flag.wav"/>
```

Server kemudian menjalankan:

```text
espeak-ng -m
```

Karena `-m` aktif, string tersebut dibaca sebagai markup.

Bagian:

```xml
<audio src="flag.wav"/>
```

tidak dibaca sebagai kata-kata.

Sebaliknya, eSpeak mengambil:

```text
flag.wav
```

dan memasukkannya ke output audio.

---

# 17. Ini Merupakan Injection Chain

Exploit sebenarnya terdiri dari dua tahap injection:

### Tahap 1 — Audio → Whisper

Kita melakukan adversarial audio attack:

```text
WAV
 ↓
Whisper
 ↓
malicious transcript
```

### Tahap 2 — Transcript → eSpeak

Transcript kemudian menjadi markup:

```text
malicious transcript
 ↓
eSpeak markup parser
 ↓
<audio src="flag.wav"/>
 ↓
flag.wav
```

Jadi keseluruhan chain:

```text
Adversarial Audio
       ↓
Whisper BPE token injection
       ↓
SSML injection
       ↓
Audio file inclusion
       ↓
flag.wav
```

---

# 18. Mengekstrak Flag dari Response

Server mengembalikan audio.

Audio tersebut disimpan sebagai:

```text
output/flag-audio.wav
```

Kemudian dilakukan ASR ulang.

Solver menggunakan dua model:

```text
medium.en
turbo
```

Keduanya digunakan karena karakter yang sama dapat menghasilkan interpretasi berbeda pada ASR.

---

# 19. Masalah Ambiguitas `B` vs `D`

Hasil transkripsi pertama menunjukkan ketidakpastian:

```text
...663BB...
```

versus:

```text
...663DD...
```

Jadi bagian flag belum dapat langsung dipastikan.

Kandidat:

```text
PWNSEC{2B1BA663BB AEE8A5}
```

dan:

```text
PWNSEC{2B1BA663DD AEE8A5}
```

perlu dibandingkan dengan audio asli.

---

# 20. Audio Alignment

Script:

```text
analysis/compare_espeak.py
```

digunakan untuk menguji kedua kandidat.

Kandidat disintesis menggunakan environment yang sama dengan server:

```text
eSpeak NG 1.51
language = en-us
speed = 110
```

Kemudian audio sintetis dibandingkan dengan audio flag asli.

Metric yang digunakan antara lain:

```text
cosine similarity
normalized RMSE
```

---

# 21. Hasil Perbandingan

### Kandidat `DD`

```text
Cosine similarity:
0.999999981

Normalized RMSE:
0.000193
```

### Kandidat `BB`

```text
Cosine similarity:
0.185697593
```

Perbedaannya sangat besar.

Kandidat `DD` hampir identik dengan audio asli.

Dengan demikian bagian yang ambigu dipastikan sebagai:

```text
DD
```

---

# 22. Flag Final

Hasil akhir:

```text
PWNSEC{2B1BA663DDAEE8A5}
```

Solver juga memverifikasi hasil tersebut dengan exit code:

```text
0
```

dan tidak menghasilkan error pada stderr.

---

# 23. Solver

File utama:

```text
solve.py
```

Struktur kerja solver:

```text
1. Load instance.json
2. Decode base64
3. Decompress gzip
4. Upload WAV
5. Terima audio response
6. Transcribe dengan medium.en
7. Transcribe dengan turbo
8. Koreksi karakter ambigu
9. Print flag
```

Perintah menjalankan solver:

```bash
python -m pip install -r ../../requirements.txt
python -m pip check
python solve.py
```

---

# 24. Analisis Source Solver

Bagian payload:

```python
PAYLOAD_B64 = """..."""
```

menyimpan WAV hasil optimisasi.

Payload kemudian didecode.

Konsep:

```python
raw = base64.b64decode(PAYLOAD_B64)
wav = gzip.decompress(raw)
```

Request dilakukan menggunakan:

```python
requests
```

dan hasil response disimpan untuk diproses ulang.

---

# 25. Kenapa Tidak Langsung Meminta Whisper Mengucapkan `<audio>`?

Karena decoding Whisper bukan sekadar text generation bebas.

Whisper mempunyai bias dan suppression terhadap token tertentu.

Jika kita hanya menggunakan audio yang mengucapkan:

```text
less than audio greater than
```

hasilnya mungkin:

```text
less than audio greater than
```

bukan:

```xml
<audio>
```

Kita membutuhkan representasi token yang tepat.

Karena itu adversarial optimization jauh lebih efektif.

---

# 26. Kenapa Harus Mencari Token Gabungan?

Misalkan kita ingin:

```text
"><
```

Cara naïf:

```text
"
>
<
```

Masalah:

```text
"
>
<
```

dapat terkena suppression.

Cara exploit:

```text
."
><
```

atau kombinasi BPE lain yang menghasilkan karakter tersebut.

Dengan BPE:

```text
semantic/token restriction
        ≠
final string restriction
```

Inilah insight paling penting dari challenge.

---

# 27. Root Cause

Ada dua root cause utama.

## Root Cause 1 — Transcript Tidak Disanitasi

Program memperlakukan output ASR sebagai trusted string.

Seharusnya:

```text
Whisper output
      ↓
plain text
      ↓
escape markup
      ↓
TTS
```

bukan:

```text
Whisper output
      ↓
raw string
      ↓
SSML parser
```

---

## Root Cause 2 — File Inclusion melalui Markup

Karena eSpeak dijalankan menggunakan:

```text
-m
```

markup aktif.

Dengan demikian:

```xml
<audio src="flag.wav"/>
```

menjadi sebuah primitive file inclusion terhadap audio output.

---

# 28. Security Boundary yang Rusak

Trust boundary yang benar seharusnya:

```text
User audio
   ↓
ASR
   ↓
UNTRUSTED TEXT
   ↓
sanitize/escape
   ↓
TTS
```

Tetapi challenge melakukan:

```text
User audio
   ↓
ASR
   ↓
TRUSTED TEXT  ← salah
   ↓
SSML parser
```

Akibatnya attacker mengontrol language layer sekaligus markup layer.

---

# 29. Pelajaran dari Challenge

## 29.1. Model AI adalah bagian dari attack surface

Whisper bukan hanya komponen fungsional.

Tokenizer dan decoding behavior-nya dapat dimanfaatkan untuk:

```text
token bypass
prompt injection
markup injection
```

---

## 29.2. Filtering token tidak sama dengan filtering string

Jika filter bekerja pada:

```text
token ID
```

maka perlu dipastikan bahwa seluruh representasi BPE ekuivalen juga aman.

Contoh:

```text
token A = "<"
token B = "><"
```

Memblokir A tetapi mengizinkan B belum tentu mencegah karakter `<`.

---

## 29.3. Output AI Harus Dianggap Untrusted

Output:

```text
Whisper transcript
```

harus diperlakukan sama seperti:

```text
HTTP parameter
user input
uploaded file metadata
```

terutama jika akan diteruskan ke parser lain.

---

## 29.4. Interpreter Chaining Sangat Berbahaya

Di challenge ini ada dua interpreter:

```text
Whisper decoder
       ↓
eSpeak markup parser
```

Keluaran interpreter pertama menjadi kode/data bagi interpreter kedua.

Ini pola klasik:

```text
parser A
  ↓
parser B
  ↓
unexpected interpretation
```

---

# 30. Alur Eksploitasi Lengkap

```text
                  USER AUDIO
                      │
                      ▼
              ┌───────────────┐
              │ Whisper tiny.en│
              └───────┬───────┘
                      │
                      │ BPE token sequence
                      ▼
        The HTML code."><audio src="flag.wav"/>
                      │
                      ▼
              ┌───────────────┐
              │ espeak-ng -m  │
              └───────┬───────┘
                      │
                      │ SSML parsing
                      ▼
             <audio src="flag.wav"/>
                      │
                      ▼
                  flag.wav
                      │
                      ▼
              RESPONSE AUDIO
                      │
                      ▼
             medium.en / turbo
                      │
                      ▼
             CHARACTER RECOVERY
                      │
                      ▼
       PWNSEC{2B1BA663DDAEE8A5}
```

---

# 31. Ringkasan Teknik

| Tahap | Teknik |
|---|---|
| Recon | `/openapi.json` |
| Identifikasi pipeline | Whisper + eSpeak |
| Sink | `espeak-ng -m` |
| Payload | `<audio src="flag.wav"/>` |
| Bypass | Combined BPE tokens |
| Initial access | Adversarial audio |
| Optimisasi | Teacher-forced cross entropy |
| Robustness | 16-bit WAV quantization |
| Exfiltration | Audio inclusion |
| Recovery | ASR ulang |
| Ambiguity resolution | Audio similarity |
| Final flag | `PWNSEC{2B1BA663DDAEE8A5}` |

---

# 32. File Penting

File yang relevan dalam challenge:

```text
Speaking Stephen/
├── challenge/
│   └── README.md
│
├── analysis/
│   ├── optimize_audio.py
│   ├── compare_espeak.py
│   ├── espeak/
│   ├── target/
│   ├── probes/
│   ├── ssml/
│   └── google/
│
├── output/
│   └── flag-audio.wav
│
├── instance.json
├── solve.py
└── writeup/
    ├── en.md
    └── ko.md
```

Direktori:

```text
analysis/espeak/
```

berisi environment eSpeak yang digunakan untuk eksperimen.

Sedangkan:

```text
analysis/target/
```

berisi audio target.

Probe:

```text
analysis/probes/
```

digunakan untuk eksperimen terhadap format audio dan transcript.

---

# 33. Kesimpulan

**Speaking Stephen** bukan sekadar challenge speech recognition.

Inti challenge adalah menemukan bahwa output Whisper melewati trust boundary dan diteruskan langsung ke eSpeak dalam mode markup.

Eksploitasi kemudian dilakukan dalam beberapa tahap:

```text
1. Identifikasi eSpeak sebagai SSML interpreter
2. Temukan <audio src="flag.wav"/>
3. Temukan bahwa Whisper menekan token simbol tertentu
4. Cari combined BPE tokens
5. Optimalkan waveform terhadap target token sequence
6. Simulasikan quantization WAV
7. Upload adversarial WAV
8. Dapatkan flag.wav melalui SSML injection
9. Transcribe audio response
10. Resolve karakter ambigu dengan audio similarity
```

Insight terpenting adalah:

> **Filter terhadap token bukanlah filter terhadap string akhir.**

Selama tokenizer masih mempunyai token gabungan yang dapat menghasilkan karakter yang diinginkan, suppression token dapat dilewati.

Pada sisi keamanan aplikasi AI, pelajaran utamanya bahkan lebih umum:

> **Output model harus dianggap sebagai untrusted input ketika diteruskan ke interpreter, parser, template engine, shell, markup processor, atau subsystem lain.**

---

# 34. Flag

```text
PWNSEC{2B1BA663DDAEE8A5}
```

**Solved.**
