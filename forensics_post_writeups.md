## Quick Mistake
> Flag: nite{192.0.2.66_2457ce19cb87e0eb_qu1c_d4t4gr4m_pwn3d}

### Solution:
- Handout include a `.pcap` file, which we can open in wireshark
- TCP can be ignored, HTTP didn't have any useful info in these packets and also NBNS contained garbage info
- If we filter specifically got `QUIC` protocol
- We can use tshark command: `tshark -r challenge.pcap -Y "quic.long.packet_type == 0" -T fields -e frame.time_relative -e ip.src -e quic.scid` to identify all IP addresses involved and SCIDs:
```
2.000000000     198.51.100.10   2457ce19cb87e0eb
2.009435000     203.0.113.100   d9cb957fd807846c,d9cb957fd807846c
2.015370000     198.51.100.10   2457ce19cb87e0eb,2457ce19cb87e0eb
2.041834000     192.0.2.66      2457ce19cb87e0eb
2.552244000     198.51.100.5    469cde6235063714
2.556851000     203.0.113.100   c55ae69d16917222,c55ae69d16917222
2.558385000     203.0.113.100   c55ae69d16917222,c55ae69d16917222
2.566020000     198.51.100.5    469cde6235063714,469cde6235063714
```
- The attacker's SCID is `2457ce19cb87e0eb`
- When we look through packet `182`
```
6c(Q1E@iqd3dQS]{"type": "telemetry_sslkeylog", "seq": 0, "total_chunks": 2, "nonce_b64": "S459VmTWtpNcz+NU", "ct_b64": "D4Y706RkRpgzXAOAWe4eKyE3AjfFXxOgxXGV7SsKeH4umYbfaY6VMedKeghapSgIyghK7rLSJxwRWwDREt1sN+ZV3MPnw4CdaqOWdh3o3dLtlyJSsDg9iYYAynV68VaXKQna5xFGaFr9x0b3vuvbFTJ7u3zgTlAmpEutj0F4leuLZDGRZupvr9+jyNLxnGNVxNXwLTcYSIR1iTOUdao/252x4H9c7DjCeuvCDX4hYfPv+l5g8JEuwutqCbdzn3nVkL4s0931lT8wpkV4suIR+0bV+X4SU8pd6XlrkxweEWpVIbJkhqnKh5driyqA/1TneBVZKS03k7TiX9ZXqmVhS4r3BKrk7wMnVwQLSLmC07UOvIEsqzWp0GJnYvyGV1FzB7Tw4JXakoLhOGs+ocpGr2PuhSrUTiAW465ikw3+lsEnKI/OFG7I+2nVjKkBA09bu17iJHNoOD3rmQ0cRGiJ8/Vr3YufXeQDMn/REyoG+Wnv/P5rR1I/O6qn/5LHiWSqaNWpg7jjRvU/pt4KBPMMTckeXTseYUwts0Ntk7IBBztYnmq1zZSNhdAZ+KQQ1/8I/lJVdgg5YWZSdepexZVJuiofPgYN55fnvWqK/LxmVE4D3gOKKbJWCQoL1FgadmZ4iX99MjYzs2qsOp9m8i1yvrMbQ4emX7hjjk74I5rfZ9E+01bBvLiw4smdlBiT4ztWA/uQPYqZC/kN06Fu9LTYTCGR8/B/4mAlKUh6ZzQDePGrYiuR0k5/WRH2fzcYnUAt5NOt6akHE3ljXOW28PV2G5IL94IxPYkITHNPTMp2J84QcuozCHtf9ex/b3fG+DLPXT0zrxh5j11SsCTULPUmLXKKqCXc/NHaxHrquM7PUZi5fQZ7Jmz386K+2ExR4ycTNVSB2MuPDzvG+FPQP60M6varPywdWM6lM7IrDQ02lXC7/n9o+m60uIjfI52IvDe4b2NFJQeU2dFPKkAX1N68yWGc75IVz2noScPqaq4P978sT+z9DfKOe0ifQc0So8qoi2WHKvB5bEUjFezszGhWzq7rJ7toUu5rg+t5i9Tuf/qpFZfcwBHyPr8o6bmkLj0p9IsEldTKUZiD4Ng8ReYn9pwwc6weeZ02D432ziDSxwIB5NA/32GV50hT+4EvTeo1cCyyGxT9Na+Qd3RVoJgO4TDWTLYwVI/x2cFa88WbAjMHveWGGiEK5TZD3Ad2Jkj3UmTj0ETTuzW1aTqTHEfVY+7A/XTNN3E1Q4VB2+e+p2JxybXgvYSmhX0aQuzmqwXhRmA8BnpBBvwl/99rKQLdJUPnnrre06Om8Azi81212PaQtiq+IEuMWg==", "tag_b64": "ElHxGRAt7wicOe+lFkLiaw=="}
```
- There is something called `telemetry_sslkeylog` and it has structure of `AEAD` which we can infer from  presence of `nonce`, `ct` and `tag`
- If we look at size of `nonce_b64` it is 12 bytes, which is same as `AES-GCM`, and also it is one of the most common types of `AEAD`
- So we can kinda conclude it is `AES-GCM`
- Also if we inspect other packets, we can find few useful leaks
- Packet 180:
```
6c(Q1E@qd3dQS{"type": "handshake_init", "seed": "af717e2c8789db71fe624598faba3953c23fdb685e6b8cd2e6f84beef0c57175", "salt": "telemetry", "info": "sslkeylog"}
```
- This has seed, salt and info in it, which can be used for descryption
- We can use python file with this information to decrypt it:
```py
import json
import binascii
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys

SEED_HEX = "af717e2c8789db71fe624598faba3953c23fdb685e6b8cd2e6f84beef0c57175"
SALT = b"telemetry"
INFO = b"sslkeylog"

CHUNKS = [
    {
        "type": "telemetry_sslkeylog",
        "seq": 0,
        "total_chunks": 2,
        "nonce_b64": "S459VmTWtpNcz+NU",
        "ct_b64": "D4Y706RkRpgzXAOAWe4eKyE3AjfFXxOgxXGV7SsKeH4umYbfaY6VMedKeghapSgIyghK7rLSJxwRWwDREt1sN+ZV3MPnw4CdaqOWdh3o3dLtlyJSsDg9iYYAynV68VaXKQna5xFGaFr9x0b3vuvbFTJ7u3zgTlAmpEutj0F4leuLZDGRZupvr9+jyNLxnGNVxNXwLTcYSIR1iTOUdao/252x4H9c7DjCeuvCDX4hYfPv+l5g8JEuwutqCbdzn3nVkL4s0931lT8wpkV4suIR+0bV+X4SU8pd6XlrkxweEWpVIbJkhqnKh5driyqA/1TneBVZKS03k7TiX9ZXqmVhS4r3BKrk7wMnVwQLSLmC07UOvIEsqzWp0GJnYvyGV1FzB7Tw4JXakoLhOGs+ocpGr2PuhSrUTiAW465ikw3+lsEnKI/OFG7I+2nVjKkBA09bu17iJHNoOD3rmQ0cRGiJ8/Vr3YufXeQDMn/REyoG+Wnv/P5rR1I/O6qn/5LHiWSqaNWpg7jjRvU/pt4KBPMMTckeXTseYUwts0Ntk7IBBztYnmq1zZSNhdAZ+KQQ1/8I/lJVdgg5YWZSdepexZVJuiofPgYN55fnvWqK/LxmVE4D3gOKKbJWCQoL1FgadmZ4iX99MjYzs2qsOp9m8i1yvrMbQ4emX7hjjk74I5rfZ9E+01bBvLiw4smdlBiT4ztWA/uQPYqZC/kN06Fu9LTYTCGR8/B/4mAlKUh6ZzQDePGrYiuR0k5/WRH2fzcYnUAt5NOt6akHE3ljXOW28PV2G5IL94IxPYkITHNPTMp2J84QcuozCHtf9ex/b3fG+DLPXT0zrxh5j11SsCTULPUmLXKKqCXc/NHaxHrquM7PUZi5fQZ7Jmz386K+2ExR4ycTNVSB2MuPDzvG+FPQP60M6varPywdWM6lM7IrDQ02lXC7/n9o+m60uIjfI52IvDe4b2NFJQeU2dFPKkAX1N68yWGc75IVz2noScPqaq4P978sT+z9DfKOe0ifQc0So8qoi2WHKvB5bEUjFezszGhWzq7rJ7toUu5rg+t5i9Tuf/qpFZfcwBHyPr8o6bmkLj0p9IsEldTKUZiD4Ng8ReYn9pwwc6weeZ02D432ziDSxwIB5NA/32GV50hT+4EvTeo1cCyyGxT9Na+Qd3RVoJgO4TDWTLYwVI/x2cFa88WbAjMHveWGGiEK5TZD3Ad2Jkj3UmTj0ETTuzW1aTqTHEfVY+7A/XTNN3E1Q4VB2+e+p2JxybXgvYSmhX0aQuzmqwXhRmA8BnpBBvwl/99rKQLdJUPnnrre06Om8Azi81212PaQtiq+IEuMWg==",
        "tag_b64": "ElHxGRAt7wicOe+lFkLiaw=="
    },
    {
        "type": "telemetry_sslkeylog",
        "seq": 1,
        "total_chunks": 2,
        "nonce_b64": "tXd5ku7fU1lPn/D9",
        "ct_b64": "o6vvBmgm6Iyj9/RRUjDdqtcFj6tn4E/7whY/4do67UD3NgRHqicb3eWZ+O8xvMaok+MHjhRreah9QQS1NEy+fAbDGMhqVqwqeNS6F5j+MOv7UX7N1wn2ZyaIxT2UogGb6D2c+F7rnaJZdpsrDQ/ZEwQTaJVuHGNTQM1klV+UZOUJ4mZzSp+/u8M1p/JJrDcMjzaGypiP7HrZ+g6FGkL83PCzWKGSVw/3syZtuzu65Owtk5XbYqDRn7MN1rYeuCzoYlSoQ3ZccUQkk9+U4BTfgImBlBqT3D3byVxqMuz5JR6MyK/AGkUXpn2qaBtX00rEtKhnJ7iLRkkBVeXbUd/rWqUfGpf6QpOEiVQeA17p80mw5g68X52u03388XhfIbfR/qehWE7wK/t8O90/CiTNvCrhFgNg5Kvze/zgDz0lJ2h3sCoThsUjP6m3lXV6rYFnswLr6fmvD26tU3+wrmSvdBbHfaLovLmmBtI9bjDw44vpgNQ4HxttPiPllYZXZYvhTrs7P4XDDqDGRHwiHn0AmDR79UVrVO0ie5RsQt91wMT+3OhxiScRiH+xw7RpTd6wb3SLNcNwVQSc+zm3ZLBv8cNGj6TknRhbcSkZxmK7yANX3FcorjuGJDd+5kSzzOihuEw8qXVLXI0XLHtL7wz7nWDP8bKLIYvOVRd59aRnOuuH9dCD4Zc5",
        "tag_b64": "ZlYYx1K6YiALxD0Tm9k6/w=="
    }
]

def derive_key(seed_hex, salt, info):
    seed = bytes.fromhex(seed_hex)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(seed)

def main():
    print(f"[*] Deriving key from Seed: {SEED_HEX}")
    key = derive_key(SEED_HEX, SALT, INFO)
    aesgcm = AESGCM(key)
    print(f"[*] Decrypting {len(CHUNKS)} chunks...")
    sorted_chunks = sorted(CHUNKS, key=lambda x: x['seq'])
    final_payload = b""
    for c in sorted_chunks:
        nonce = binascii.a2b_base64(c['nonce_b64'])
        ct = binascii.a2b_base64(c['ct_b64'])
        tag = binascii.a2b_base64(c['tag_b64'])
        full_ct = ct + tag
        try:
            pt = aesgcm.decrypt(nonce, full_ct, None)
            final_payload += pt
        except Exception as e:
            print(f"[-] Decryption failed for chunk {c['seq']}: {e}")
            return
    try:
        print("\n--- RECOVERED SSLKEYLOGFILE ---")
        print(final_payload.decode('utf-8'))
        print("--- END ---")
    except UnicodeDecodeError:
        print("\n--- RECOVERED BINARY DATA ---")
        print(final_payload)

if __name__ == "__main__":
    main()
```
- Thus we can recover sslkeylog:
```
SERVER_HANDSHAKE_TRAFFIC_SECRET 2500f732f1653ee3aa00e12b7eea74bdc84560352704f4fa3867230be10e6dc9 e421ab3034c3cdaf1bb56a74ac96db33cba69e9ec0daca8cb69cc4cf761e75551271b55e0bc74147c4fd2d3bd45e7f59
CLIENT_HANDSHAKE_TRAFFIC_SECRET 2500f732f1653ee3aa00e12b7eea74bdc84560352704f4fa3867230be10e6dc9 46ade76c21960f046d1e1e3eb7a311482f72bf7041056e1e727a0f953d63fddf54c8f461aaf36e3dfe0ae9742aeab454
SERVER_TRAFFIC_SECRET_0 2500f732f1653ee3aa00e12b7eea74bdc84560352704f4fa3867230be10e6dc9 d27b5c13de392011407a9f4739cade8d2f047752ae5a53ca8ac49452e6103f7d096bb5e85d57797f5b361c584d572100
CLIENT_TRAFFIC_SECRET_0 2500f732f1653ee3aa00e12b7eea74bdc84560352704f4fa3867230be10e6dc9 f6e203086a332394c865850c7f9c5b36b1c078c7eb01324cdc2c7f0fc6fc2df81944629ca95e5764e077fd9fd5063123
SERVER_HANDSHAKE_TRAFFIC_SECRET 01676c117a664530defc6fd00bb78985944d921bb57171279328f764e5b36a0c e30b264c1fb7f0702e23a820d7e2e2a1162513bcc9f306d8ddb1bdff5a7b98736ee1d0ecbfde175a2ed1d5b61855c0db
CLIENT_HANDSHAKE_TRAFFIC_SECRET 01676c117a664530defc6fd00bb78985944d921bb57171279328f764e5b36a0c ccd0dbf8360ce945904fc829d4aba0399cafe136bd337e5f5ed763581020124e0949ae8421ca376908b033f58a56026e
SERVER_TRAFFIC_SECRET_0 01676c117a664530defc6fd00bb78985944d921bb57171279328f764e5b36a0c 3931307751f68414b2a19a4ee700129f5f4f207713d83f90fc8e74acf62bd7a32f20080c5b65cea403f68bf8f02cd64c
CLIENT_TRAFFIC_SECRET_0 01676c117a664530defc6fd00bb78985944d921bb57171279328f764e5b36a0c 995c5a4793726dc86ffa8583bf7a45eec86e07fb7f911f893005fdc4c820c7fd52d132ba4514b4e6319ca2818ada94e0
```
- Now we can attatch this to `Tools > TLS Keylog Launcher`
- Now when we reload the `.pcap` file, we can filter to view http3 protocol
- If we check the data in requeset for `/source`:
<img width="2560" height="1418" alt="image" src="https://github.com/user-attachments/assets/8cdc9ebe-bc05-4b1f-a87e-13476b5d78e9" />

- From `IF 8b` we can infer it is `tar.gz` as that's the header for it
- Then we can right click and press on save bytes as `.tar.gz`
<img width="1465" height="749" alt="image" src="https://github.com/user-attachments/assets/aadfbc7d-2ebf-44cc-8e17-6d6fcd14c831" />

- This gives us a proper tar archive file
- We can get `AES_FLAG_KEY=wEN64tLF1PtOglz3Oorl7su8_GQzmlU2jbFP70cFz7c=` from `.env`
- If we check data of `/flag` we get: `gAAAAABpNXDCHUJ4YqH0Md2p6tzE303L8z5kPpPPWwYYrXUdiyW89eCaWWL1dbYU2JYj7SUvdwySW_egZDRF0fyFGxPua2KoFmd8upKP7cZv55jVp_SzItA=`
- This is header for Fernet encryption
- Now we can use a python script to decrypt and find the flag
```
from cryptography.fernet import Fernet, InvalidToken

KEY = b"wEN64tLF1PtOglz3Oorl7su8_GQzmlU2jbFP70cFz7c="
TOKEN = b"gAAAAABpNXDCHUJ4YqH0Md2p6tzE303L8z5kPpPPWwYYrXUdiyW89eCaWWL1dbYU2JYj7SUvdwySW_egZDRF0fyFGxPua2KoFmd8upKP7cZv55jVp_SzItA="

def main():
    f = Fernet(KEY)
    try:
        pt = f.decrypt(TOKEN)
        try:
            print(pt.decode("utf-8"))
        except:
            print(pt)
    except InvalidToken:
        print("Invalid key or token.")

if __name__ == "__main__":
    main()
```

---

## quite OKNOTOK
> Flag: nite{q01_n0_y0q0an}

### Solution:
- Once we download the audio file, we can infer from header that it is a `QOA` file
- We can convert it to `.wav` and open in spectrogram, we can see alternating frequencies and `msb`, `lsb` written
- We can use a python script that converts these to 0s and 1s (i.e bits)
```
import numpy as np
from scipy.io import wavfile
from scipy.fft import fft, fftfreq
freq_pairs = [
    (7500, 7700), # msb
    (8500, 8700),
    (9500, 9700),
    (10500, 10700),
    (11500, 11700),
    (12500, 12700),
    (13500, 13700),
    (14500, 14700) # lsb
]
def parse_audio(audio):
    rate, data = wavfile.read(audio)
    if data.ndim > 1:
        data = data[:,0]
    samples = int(0.1*rate) # duration = 0.1s
    symbols = len(data) // samples
    binarystr = []
    for i in range(symbols):
        chunk = data[i*samples:(i+1)*samples]
        yf = np.abs(fft(chunk * np.hanning(len(chunk))))
        xf = fftfreq(len(chunk), 1/rate)
        xf, yf = xf[:len(xf)//2], yf[:len(yf)//2]
        bits = []
        for f0, f1 in freq_pairs:
            i0 = np.argmin(np.abs(xf - f0))
            i1 = np.argmin(np.abs(xf - f1))
            bits.append('0' if yf[i0] > yf[i1] else '1')
        binarystr.append(''.join(bits))
    return ''.join(binarystr)
print(parse_audio("binaural_beats.wav"))
```
- From hex of file we can infer it is a `QOI` file (same header)
- Once we open it in gimp we can view half right side of QR, we can clean it by converting brown pixels to white
- We can use [QRazyBox](https://merri.cx/qrazybox/) and select Extract QR information in tools section to get `pastebin.com/kdhd1pSD`
- The pastebin link has a base64 string which we can decode to get `katb.in/onahadivala` which is labelled part 2
- We can now open the link to get another base64 string which can be decoded to one more `QOI` image
- Once we open it in GIMP, we see a line of coloured strip and text saying `p2: rgba`
- We can use `stegsolve` after converting both QOIs to PNGs and obtain the first part of flag from decoded image: `nite{q01_`
- Now focusing back to part 2
- We can check comments of pastebin to obtain more base64 strings and also tag of pastebin leads to `https://en.wikipedia.org/wiki/QOI_(image_format)#QOI_OP_INDEX`
- Scrolling a bit above we can find `index_position = (r * 3 + g * 5 + b * 7 + a * 11) % 64` , this is useful for the strip we found earlier in second QOI image
- We can use all these clues and python script:
```py
from PIL import Image
import base64

img = Image.open("colorstrip.png").convert("RGBA")
width, height = img.size
colors = []
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" # base 64 character mapping

for y in range(height):
    r,g,b,a = img.getpixel((0,y))
    colors.append((r,g,b,a))
print(colors)

indices = [(3*r + 5*g + 7*b + 11*a) % 64 for r, g, b, a in colors] # QOI encoding index hash function
print(base64.b64decode(''.join(alphabet[i] for i in indices)))
```
- Thus we get second part of flag: `n0_y0q0an}`

