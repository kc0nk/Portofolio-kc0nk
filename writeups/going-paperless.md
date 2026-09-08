# Going Paperless

- **Category:** Program
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
Puzzle encoding sederhana: printer mengubah karakter menjadi angka desimal ASCII.

## Metode
Map each decimal number to its ASCII character.

## Input
```text
98 114 117 110 110 101 114 123 97 115 99 105 105 95 103 114 101 101 110 119 97 115 104 105 110 103 125
```

## Rumus / constraint
```text
ASCII decimal → chr(number) → plaintext
```

## Solver / code snippet
```python
nums = [98,114,117,110,110,101,114,123,97,115,99,105,105,
        95,103,114,101,101,110,119,97,115,104,105,110,103,125]
print(''.join(map(chr, nums)))
```

## Hasil
```text
brunner{ascii_greenwashing}
```
