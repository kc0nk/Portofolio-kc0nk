# Null0rigin CTF 2026 — Forensics Chain 15: Handoff

## Challenge

**Name:** Handoff  
**Category:** Network / Forensics  
**Difficulty:** Easy  

> A handoff is the moment a thing stops being one party's problem.  
> It is also the moment nobody is quite watching.

The previous stage also hinted:

> the picture is not in any one frame

**Flag format**

```text
Null0rigin{lowercase_words_with_underscores}
```

---

## Summary

The supplied network capture contains RTP traffic on UDP port `5004`.

There are **two RTP SSRC streams** using the same rendezvous point. Looking at individual packets does not reveal the image because each RTP payload carries only a **single binary scanline**.

The solution is to:

1. isolate each SSRC;
2. order packets correctly;
3. extract the RTP payloads;
4. stack the scanlines into an image;
5. compare the two reconstructed screens.

One stream reconstructs a decoy screen.  
The other reconstructs the real flag:

```text
Null0rigin{the_right_feed_never_lied}
```

---

## 1. Inspect the Capture

Start with basic PCAP triage:

```bash
capinfos <capture.pcapng>
tshark -r <capture.pcapng> -q -z conv,udp
```

UDP/5004 stands out as the relevant traffic.

Inspect it:

```bash
tshark -r <capture.pcapng> \
  -Y 'udp.port == 5004'
```

Because port 5004 is commonly used for RTP, force RTP decoding if Wireshark does not automatically recognize it:

```bash
tshark -r <capture.pcapng> \
  -d udp.port==5004,rtp \
  -Y rtp
```

---

## 2. Notice the Two SSRC Values

RTP identifies independent synchronization sources using the **SSRC** field.

List them:

```bash
tshark -r <capture.pcapng> \
  -d udp.port==5004,rtp \
  -Y rtp \
  -T fields \
  -e rtp.ssrc | sort -u
```

The capture contains two distinct SSRC streams.

This is the "handoff" clue: two feeds occupy the same transport context, and blindly combining them produces nonsense.

---

## 3. Understand the Payload

Inspect sequence numbers, timestamps, SSRC values, and payload bytes:

```bash
tshark -r <capture.pcapng> \
  -d udp.port==5004,rtp \
  -Y rtp \
  -T fields \
  -e rtp.ssrc \
  -e rtp.seq \
  -e rtp.timestamp \
  -e rtp.payload
```

The important discovery is that each payload is not a complete image.

Each packet contains one **binary image row / scanline**.

That explains the previous-stage hint:

```text
the picture is not in any one frame
```

The image only appears after many packets are reconstructed in order.

---

## 4. Reassemble Each SSRC Separately

Do **not** mix both RTP feeds.

For each SSRC:

1. filter packets belonging to that SSRC;
2. sort by RTP sequence number;
3. convert the payload hex to raw bytes;
4. interpret each payload as one image row;
5. stack the rows vertically.

A simple reconstruction script can look like this:

```python
import subprocess
from pathlib import Path
from PIL import Image

PCAP = "capture.pcapng"
SSRC = "0x12345678"   # replace with one SSRC from the capture

cmd = [
    "tshark",
    "-r", PCAP,
    "-d", "udp.port==5004,rtp",
    "-Y", f"rtp.ssrc == {SSRC}",
    "-T", "fields",
    "-e", "rtp.seq",
    "-e", "rtp.payload",
]

out = subprocess.check_output(cmd, text=True)

rows = []

for line in out.splitlines():
    if not line.strip():
        continue

    seq, payload = line.split("\t", 1)
    raw = bytes.fromhex(payload.replace(":", ""))
    rows.append((int(seq), raw))

rows.sort(key=lambda x: x[0])

# One packet = one scanline.
width = len(rows[0][1]) * 8
height = len(rows)

img = Image.new("1", (width, height))
pix = img.load()

for y, (_, row) in enumerate(rows):
    bit_index = 0
    for byte in row:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            pix[bit_index, y] = 255 if bit else 0
            bit_index += 1

img.resize((width * 4, height * 4)).save(f"{SSRC}_screen.png")
```

Depending on the payload bit order, it may be necessary to reverse the bit order inside each byte or invert black/white.

The important point is to reconstruct **each SSRC independently**.

---

## 5. Reconstructed Screens

One SSRC produces the decoy:

```text
Null0rigin{the_ghost_signal_answered}
```

The other SSRC produces:

```text
Null0rigin{the_right_feed_never_lied}
```

The decoy is intentionally plausible. The verifier even warns about choosing the wrong stream:

```text
That's the OTHER kiosk. Wrong SSRC, wrong screen.
```

So the correct solution is not simply "find any readable flag."  
It is "identify the correct RTP feed."

---

## 6. Why the Correct Feed Matters

Both feeds travel through the same apparent network handoff.

At packet level, neither one packet nor one generic UDP conversation is enough to identify the answer.

RTP's SSRC field is the metadata that separates the two logical sources.

That is the core forensic idea behind the challenge:

```text
same port
same protocol
same capture

different source identity
different reconstructed screen
```

The "right feed" is literally the correct SSRC.

---

## 7. Recovered Flag

```text
Null0rigin{the_right_feed_never_lied}
```

The supplied verifier confirmed:

```text
CORRECT. handoff solved.
```

---

## Takeaways

- RTP streams must be separated by SSRC, not merely by UDP port.
- Sequence numbers matter when reconstructing packetized media/data.
- A packet payload can represent only a fragment of a larger artifact.
- Visual reconstruction is often more useful than searching packet bytes for printable strings.
- In CTFs with decoys, a readable flag is not enough—confirm which logical source produced it.

---

## Final Flag

```text
Null0rigin{the_right_feed_never_lied}
```
