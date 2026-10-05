# Sanity -2

**Category:** Misc / Sanity  
**Points:** 100

## Challenge

> Have you checked our websites properly? 👀
>
> The interesting stuff is hiding where you least expect it. Maybe look around a little… and don’t give up after the first find. 🕵️‍♂️
>
> btw I'm not a cat lover
>
> `part1 + part2`

## Solution

The challenge mentions multiple **websites**, says not to stop after the first discovery, and explicitly asks us to combine two parts. The cat reference hints at the Unix `cat` command.

### Part 1: CyberHX terminal

Open the CyberHX website and navigate to its About page:

```text
https://cyberhx.com/about
```

The page contains an interactive terminal. Running `ls` lists a suspicious file named `flag.txt`:

```console
$ ls
Available pages:
about/
themes/
timeline/
gallery/
prizes/
flag.txt
```

The challenge's “cat lover” hint points to reading it with `cat`:

```console
$ cat flag.txt
Null0rigin{y8u_d1d_
```

Therefore:

```text
part1 = Null0rigin{y8u_d1d_
```

The same value is visible in the page's lazy-loaded JavaScript bundle, where the simulated terminal handles the `cat flag.txt` command.

### Part 2: NullOrigin console

Next, visit the official NullOrigin event website:

```text
https://nullorigin.cyberhx.com/
```

Opening the browser developer console reveals a message containing this Base64 string:

```text
ZmxhZ3tjMG5zMGwzX3IzYzBuX3A0eXNfMGZmfQ==
```

Decode it with either a shell or Python:

```bash
echo 'ZmxhZ3tjMG5zMGwzX3IzYzBuX3A0eXNfMGZmfQ==' | base64 -d
```

```python
import base64

value = "ZmxhZ3tjMG5zMGwzX3IzYzBuX3A0eXNfMGZmfQ=="
print(base64.b64decode(value).decode())
```

The decoded result is:

```text
flag{c0ns0l3_r3c0n_p4ys_0ff}
```

This wrapper indicates the meaningful second fragment is:

```text
part2 = c0ns0l3_r3c0n_p4ys_0ff}
```

### Combine the parts

The challenge explicitly specifies `part1 + part2`:

```text
Null0rigin{y8u_d1d_ + c0ns0l3_r3c0n_p4ys_0ff}
```

## Flag

```text
Null0rigin{y8u_d1d_c0ns0l3_r3c0n_p4ys_0ff}
```
