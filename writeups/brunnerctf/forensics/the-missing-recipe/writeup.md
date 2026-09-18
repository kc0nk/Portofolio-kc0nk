# The Missing Recipe

- **Category:** Forensics
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Analisis PCAP untuk merekonstruksi serangan dan mengambil recipe rahasia. Jalur utama memakai DNS tunneling/data exfiltration, decoding Base32/AES, lalu ekstraksi payload.

## Metode
PCAP triage → DNS filter → reconstruct chunks → Base32/AES → zstd/PNG extraction.

## Command / primitive
```bash
file the-missing-recipe.pcap
strings -a -n 6 the-missing-recipe.pcap
# dns
# dns.qry.name contains "targwuwrnhos.com"
# ip.addr == 192.168.1.100
zstd -d payload.zst
grep -oba $'\x89PNG\r\n\x1a\n' the-missing-recipe.pcap
```

## Rumus / constraint
```text
DNS labels → Base32 decode → AES decrypt → compressed payload → artifact
```

## Solver / code snippet
```python
# Conceptual pipeline
chunks = extract_dns_labels(pcap)
blob = base64.b32decode("".join(chunks))
plain = AES.decrypt(blob, key)
open("payload.zst", "wb").write(plain)
```

## Hasil
```text
brunner{k33p_53nd1ng_th3_me55ag3s}
```
