# Why those random letters?

- **Category:** Cryptography

## Ringkasan
Every plaintext character becomes ASCII+1 followed by a random decoy. The decoy is always at an odd index.

## Teknik
Take even indices, subtract one from ASCII.

## Rumus / constraint
```text
C[2i]=P[i]+1
C[2i+1]=r_i
P[i]=C[2i]−1
```

## Solver inti
```python
ciphertext=r'cqsWvloGoWfGsv|LXS4e`YEI4E5EmJuL`ExB2Fuuii`qSV5LoLeUpbnH\"W~n'
plaintext=''.join(chr(ord(ciphertext[i])-1) for i in range(0,len(ciphertext),2))
print(plaintext)
```

## Hasil
```text
brunner{W3_D34lt_w1th_R4ndom!}
```
