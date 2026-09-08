# Legacy Cipher

- **Category:** Cryptography

## Ringkasan
Classic Caesar cipher. The keyspace is only 26 shifts; the supplied ciphertext uses shift 3.

## Teknik
Direct inversion / exhaustive 26-shift search.

## Rumus / constraint
```text
C=(P+k) mod 26
P=(C−k) mod 26
k=3
```

## Solver inti
```python
ciphertext='euxqqhu{fdhvdu_flskhu_lv_hdvb}'
def dec(text,s):
    return ''.join(chr((ord(c)-97-s)%26+97) if 'a'<=c<='z' else c for c in text)
for s in range(26):
    p=dec(ciphertext,s)
    if p.startswith('brunner{'): print(p)
```

## Hasil
```text
brunner{caesar_cipher_is_easy}
```
