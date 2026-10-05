# Null0rigin CTF 2026 — Forensics Chain 14: Slackwater

## Challenge

**Name:** Slackwater  
**Category:** Forensics  
**Difficulty:** Easy  

> Slack water is the turn of the tide, when the surface tells you nothing.  
> This came out of a device someone stopped using in a hurry.

**Flag format**

```text
Null0rigin{lowercase_words_with_underscores}
```

---

## Summary

The obvious files inside the image contained misleading material and decoy flags.  
The real clue was not in a normal file at all.

The key observation was that the FAT32 image contained **clusters marked as allocated in the FAT, but not referenced by any directory entry**. These orphaned clusters formed a hidden bitmap when their allocation state was visualized.

That bitmap revealed the real flag:

```text
Null0rigin{ink_before_dawn}
```

---

## 1. Initial Triage

Start by identifying the supplied evidence:

```bash
file *
ls -lah
```

For a FAT filesystem image, useful first checks include:

```bash
fsstat <image>
fls -r <image>
```

The normal directory tree is important, but in this challenge it is also a trap: several visible artifacts lead toward decoy material.

The challenge title **Slackwater** suggests looking beyond ordinary file contents—unused/slack/orphaned storage is the important area.

---

## 2. Inspect the FAT32 Structure

The filesystem is FAT32, so two structures matter:

- the **FAT**, which records cluster allocation/chains;
- the **directory entries**, which tell us which clusters belong to visible files/directories.

A cluster can therefore be:

1. free;
2. allocated and referenced by a file;
3. **allocated but not referenced anywhere**.

The third case is the interesting one.

List normal filesystem objects first:

```bash
fls -r -p <image>
```

This gives the set of files/directories that the filesystem itself admits exist.

Then inspect FAT allocation information using Sleuth Kit or a custom parser.

Useful tools include:

```bash
fsstat <image>
istat <image> <inode>
blkls <image>
```

For this challenge, simply carving files was not enough. The useful signal came from comparing **FAT allocation state** with **directory-referenced clusters**.

---

## 3. Identify Orphaned Allocated Clusters

Conceptually, the process is:

```text
all_allocated_clusters
        MINUS
clusters_referenced_by_directory_entries
        =
orphaned_allocated_clusters
```

These orphaned clusters are still marked "in use" by the FAT, but no normal file points to them.

That fits the story perfectly: the device was abandoned abruptly and the important data was left in a state the normal directory view no longer described.

A simple parser can:

1. read the FAT;
2. mark every non-free data cluster as allocated;
3. walk every visible FAT chain reachable from directory entries;
4. subtract the referenced set from the allocated set.

Pseudo-code:

```python
allocated = set()
referenced = set()

for cluster in fat:
    if fat[cluster] != FREE:
        allocated.add(cluster)

for entry in all_directory_entries:
    for cluster in walk_chain(entry.first_cluster):
        referenced.add(cluster)

orphans = allocated - referenced
```

---

## 4. The Decoy Trail

The evidence contains images/JPEG-like material with apparent flags.

Those are deliberate decoys.

The important lesson is:

> A printable `Null0rigin{...}` string is not automatically the answer.

In this stage, even data that looked like file slack or embedded media could lead to a plausible-looking false flag.

Because the chain verifier only allows a limited number of genuine wrong submissions, each candidate should be validated against the forensic structure before being submitted.

---

## 5. Visualize the Orphan Cluster Map

The breakthrough comes from treating orphan-cluster membership as a binary image:

```text
orphan cluster      -> 1
normal/non-orphan   -> 0
```

Arrange consecutive cluster numbers into rows of a suitable width and render them as pixels.

Example:

```python
from PIL import Image

# `bits` contains 0/1 values representing whether each cluster
# belongs to the orphaned set.
width = 80
height = (len(bits) + width - 1) // width

img = Image.new("1", (width, height))
px = img.load()

for i, bit in enumerate(bits):
    x = i % width
    y = i // width
    px[x, y] = 255 if bit else 0

img.resize((width * 8, height * 8)).save("fat_orphan_map.png")
```

Trying the correct alignment/row width turns what initially looks like allocation noise into readable text.

The bitmap spells the flag.

---

## 6. Recovered Flag

```text
Null0rigin{ink_before_dawn}
```

The supplied verifier confirmed the answer:

```text
CORRECT. slackwater solved.
```

---

## Why the Challenge Works

The filesystem has two different ideas of reality:

- the directory tree says what files exist;
- the FAT says which clusters are allocated.

Normally those views agree.

Here they do not.

The hidden message lives exactly in that disagreement—the "slack water" between what the surface reports and what the low-level filesystem still remembers.

---

## Takeaways

- Do not stop at visible files in a forensic disk challenge.
- FAT metadata can preserve evidence that directory listings no longer expose.
- Compare **allocated** clusters against **referenced** clusters.
- Orphan-cluster patterns can themselves encode information.
- Treat easy-to-find flags as suspicious when the challenge clearly contains layered forensic artifacts.

---

## Final Flag

```text
Null0rigin{ink_before_dawn}
```
