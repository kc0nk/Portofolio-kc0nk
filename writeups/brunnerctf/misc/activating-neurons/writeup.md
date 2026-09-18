# Activating Neurons

- **Category:** Misc
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Rekonstruksi neural network yang seluruhnya linear/passive. Bobot dan bias dapat diperlakukan sebagai operasi aljabar linear, lalu output dibulatkan menjadi karakter.

## Metode
Recover network matrices → multiply input → reconstruct text.

## Rumus / constraint
```text
z = W_in x + b_in
a = ReLU(z)
y = W_hidden a + b_hidden
flag = ''.join(chr(round(y[i])) ...)
```

## Solver / code snippet
```python
z = W_in @ x + b_in
a = np.maximum(z, 0)
y = W_hidden @ a + b_hidden
flag = ''.join(chr(round(v)) for v in y)
```

## Hasil
```text
brunner{ml_c4n_b3_fun_th3_m05t_1mp0rt4nt_1ngr3d13nt_15_l0v3_4nd_5ug4r}
```
