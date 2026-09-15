# TriKDF Enterprise

- **Category:** Cryptography

## Ringkasan
Triangle inequality is never validated. The malformed triangle `(1,1,65535)` forces cosine-rule arccos inputs outside `[-1,1]`, producing NaN and poisoning the eight-element state.

## Teknik
Invalid triangle → NaN state → deterministic KDF material → AES-GCM decrypt.

## Rumus / constraint
```text
α,β,γ = arccos(cosine-law argument)
(1,1,65535) ⇒ α=β=γ=NaN
state → [NaN × 8]
K = SHA256(prefix || pack(1,1,65535) || NaN_state)
```

## Solver inti
```python
a,b,c=1,1,65535
nan=float("nan")
state=b"".join(struct.pack("<d",nan) for _ in range(8))
material=b"TriKDF-v1 AES-256\x00"+struct.pack(">III",a,b,c)+state
key=hashlib.sha256(material).digest()
plain=AESGCM(key).decrypt(nonce,ciphertext,None)
```

## Hasil
```text
brunner{n0n-c0mpl14nt_Tr14ngl3s}
```
