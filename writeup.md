# OSINT

## Cornfield Chase
![zen_BAk9VHcnxt](https://github.com/user-attachments/assets/288d4001-48f9-453b-87ca-0b7129c460e7)

- The image had many clues, but the most significant was the blue sign
- It had chinese written on it with some unique codes
- I reverse searched the image and turns out it is used by Taiwan power supply
- So I went to their [website](https://data.gov.tw/en/datasets/33305) and download a csv and searched up that got
- I got some proprietary taiwan coordinates which I converted to DMS
- Then I went to that location and looked around for some time and found the exact location



## Bonsai Bankai
![zen_kMfKQtQtmB](https://github.com/user-attachments/assets/f069b871-20da-43e7-ad0f-a7139557c5bf)

- The area was obviously in Japan cause of the house structures and signs with japenese around
- I looked around and thought about reverse image searching the brows house
- I found a property seller who had address attatched to this house
- This gave me the exact coords
- I went to that spot and got the flag

## The Flash
![zen_Bb16cvZ7dg](https://github.com/user-attachments/assets/74414706-1b57-48b1-a0eb-12a6de258de4)

- The image burned my retina
- It barely had anything visible on it to figure out the place
- The electric pole was too generic and so where the yellow traffic signs
- Decided to reverse image search the vegetation and turns out Ooty has a similar scenary near it
- The pine forest area was the biggest hint
- I went to street view near there and realised the shape and structure of whole thing was similar
- Now the easy part was over and I spent 4-5 hours finding the exact spot
- Finally went a bit near city area and street view had this similar glare, so I followed the path till it reached near lake and pine tree forest
- After going up the hill a bit I found the exact area and got the flag
- Turns out it was just below the path I started with in ooty

## Hillbilly
![zen_V8IHrsIhMP](https://github.com/user-attachments/assets/452cd62b-331a-4190-8281-1c6c3842d306)

- First I tried searching for trees and turns out olive trees are common around Greece, Italy and Syria area
- The best bet for me was Greece as it has lot of area with similar olive groves
- At first I thought it was near Athens and 2 cities near it, I spent around 8 hours in this area
- Then I decided to use a filter tool for google street view before 2016, as the watermark on challenge image was 2015
- Now I scanned almost 3 cities and went around and around, the mountains there did look similar and so were trees
- There was no hope though so I decided to try out my last method
- I reverse image searched the grill/barrier in challenge image with olive tree in background
- After discaridng first few searches, I found a plot seller that had pictures of similar colour scheme, trees, soil and most importantly barriers on their (website)[https://www.rightmove.co.uk/properties/161713154?currencyCode=GBP#/media?id=media8&ref=photoCollage&channel=OVERSEAS]
- So I decided to go there and found exactly the same mountains
- I went near it and tried to find similar view/angle
- After few minutes I found similar looking groves and barriers
- Followed it and found same background too
- Thus I got the flag

## Road Not Taken
<img width="1950" height="1383" alt="image" src="https://github.com/user-attachments/assets/3fa368a6-9aac-43a7-911d-414d42301815" />

- At first I had no clue where this could be but after searching a while I found out only Ghana has black tape in front side of car
- Then I went there and looked for like an hour but it was too huge
- Later decided to search up and found there are metas for Ghana
- I decided to follow (plonkit)[https://www.plonkit.net/ghana] and (geotips)[https://geotips.net/africa/] for this
- Decided to follow tape meta on there which marked specific roads with similar tape wearing
- Then looked around and went to south and south eastern area as they are supposed to have a bit of red soil and are lush
- Looked there for hours but roads wouldn't end
- Decided to follow compass on challenge's page and looked through all north/south looking roads
- Spent around 5 hours on this as I decided to even check western and bit of northern region for north-south leading roads
- Turns out the compass was broken
- Now it clicked to me that it is obviously not a highway as the title says road not taken
- So I decided to check more roads, now based on clear sky, sun location and tape meta
- After 5-6 more hours I was near entrance of this city where I found same van in front of me as challenge
- I followed it and finally found the flag

---

# Web Exploitation

## Database Reincursion
- This one was quite tricky as it filtered `or` and `--` in login form
- I tried as many bypasses as I could online on cheat sheets and guides, but they were either filtered, or not recognized by this sql or straight up blocked cause of character limit
- Then I wondered if I tried SQLI in passwords field then it would work or not
- Suprisingly this worked:
```
username: admin
password: ' UNION SELECT '1', '2', '3' FROM users WHERE ''='
```
- Then I was inside it and now I was supposed to find kiwi (same as previous 2 database challenges)
- But this time there were filters
- So I tried to simply use `Kiwi' /*` which didn't trigger the filter and worked in search box for names
- I did find kiwi but there was limit of 4 rows so it didnt't include one from management
- I decided I need to specify both Kiwi and Management, so I used `Kiwi' AND department='Management' /*` , this again didn't trigger the filters
- Thus I found the management kiwi who had password in her notes: `ecSKsN7SES`
- Then I accessed the admin panel and similarly to older database challenge, we had to find actual name of redacted and thus I decided to find it using `' UNION SELECT 1, sql, 3, 4 FROM sqlite_master /*`
- Then I finally got the flag using `' UNION SELECT 1, secrets, 3, 4 FROM CITADEL_ARCHIVE_2077 /*`

  ---

  # Web3

## 
- Description talked about contract so I went to contract and there was a decompile button which kinda tried to find the source code
- I pressed it and got (It was cleaner and readable on site but didn't allow me to copy so I copied from dev tools which broke the format):
```
://<![CDATA[var strR = '# Palkeoramix decompiler. \n\ndef storage:\n  unknownc91d4ca6 is array of uint256 at storage 0\n  owner is addr at storage 1\n\ndef owner() payable: \n  return owner\n\ndef unknownc91d4ca6(uint256 _param1) payable: \n  require calldata.size - 4 >=ΓÇ▓ 32\n  require _param1 == _param1\n  require _param1 < unknownc91d4ca6.length\n  return unknownc91d4ca6[_param1]\n\n#\n#  Regular functions\n#\n\ndef _fallback() payable: # default function\n  revert\n\ndef unknownb8da5144() payable: \n  require calldata.size - 4 >=ΓÇ▓ 32\n  require cd <= 18446744073709551615\n  require cd <ΓÇ▓ calldata.size\n  if (\'cd\', 4).length > 18446744073709551615:\n      revert with \'NH{q\', 65\n  if (32 * (\'cd\', 4).length) + 128 > 18446744073709551615 or (32 * (\'cd\', 4).length) + 128 < 96:\n      revert with \'NH{q\', 65\n  mem[64] = (32 * (\'cd\', 4).length) + 128\n  mem[96] = (\'cd\', 4).length\n  require cd * (\'cd\', 4).length) + 36 <= calldata.size\n  idx = 0\n  s = cd[4] + 36\n  t = 128\n  while idx < (\'cd\', 4).length:\n      require cd[s] == cd[s]\n      mem[t] = cd[s]\n      idx = idx + 1\n      s = s + 32\n      t = t + 32\n      continue \n  if (\'cd\', 4).length != unknownc91d4ca6.length:\n      revert with 0, \'Wrong number of chunks\'\n  idx = 0\n  while idx < (\'cd\', 4).length:\n      if idx >= mem[96]:\n          revert with \'NH{q\', 50\n      mem[mem[64] + 32] = mem[(32 * idx) + 128]\n      mem[mem[64] + 64] = owner\n      _38 = mem[64]\n      mem[mem[64]] = 52\n      mem[64] = mem[64] + 84\n      _40 = sha3(mem[_38 + 32 len mem[_38]])\n      if idx >= unknownc91d4ca6.length:\n          revert with \'NH{q\', 50\n      mem[0] = 0\n      if _40 != unknownc91d4ca6[idx]:\n          revert with 0, \'Invalid Chunk\'\n      if idx == -1:\n          revert with \'NH{q\', 17\n      idx = idx + 1\n      continue \n  return 1\n\n\n'; window.onload = function() { decompile_pan(strR); };//]]
```
- This gave me basic idea of how it worked
- Also I checked input data of transactions and all execpt 3 were useless
- Also we required owner address to decode this
- The contract stores 8 hashes and ownner address is the salt
- So I copied all the required strings and solved it using a python script:
```py
from eth_hash.auto import keccak
import itertools
import string
import sys

owner = bytes.fromhex("1597126b98a9560ca91ad4b926d0def7e2c45603")

hashes = [
    "f59964cd0c25442208c8d0135bf938cf10dee456234ac55bccafac25e7f16234",
    "a12f9f56c9d0067235de6a2fd821977bacc4d5ed6a9d9f7e38d643143f855688",
    "3486d083d2655b16f836dcf07114c4a738727c9481b620cdf2db59cd5acfe372",
    "2dfb14ffa4d2fe750d6e28014c3013793b22e122190a335a308f0d330143da3d",
    "d62d22652789151588d2d49bcd0d20a41e2ba09f319f6cf84bc712ea45a215ef",
    "6cf18571f33a226462303a6ae09be5de3c725b724bf623b5691dcb60651ee136",
    "2b86ca86c8cfc8aa383afc78aa91ab265b174071d300c720e178264d2f647a42",
    "e9d5b7877c45245ca46dc5975dc6b577baa951b05f59a8e7b87468bfad4a956d" 

charset = string.ascii_letters + string.digits + string.punctuation

flag = ""
print(f"[-] Cracking... (Charset size: {len(charset)})")

for i, h in enumerate(hashes):
    target = bytes.fromhex(h)
    found = False
    
    for c in itertools.product(charset, repeat=4):
        word_str = "".join(c)
        word_bytes = word_str.encode()
        
        chunk = word_bytes + b"\x00" * (32 - len(word_bytes))

        if keccak(chunk + owner) == target:
            print(f"[+] Chunk {i+1} Found: {word_str}")
            flag += word_str
            found = True
            break
    
    if not found:
        print(f"Couldn't Crack")
        sys.exit()

print(f"\n[***] FINAL FLAG: {flag}")
```
- This cracked it with 94 character set
- Thus I got the flag

## Money Trail
- The description made it clear we had to go through all transactions and check input data/log for strings
- So I used python script to automate this:

```py
import requests
import time
import string
from web3 import Web3
from hexbytes import HexBytes

# --- CONFIGURATION ---
RPC_URL = "https://testnet.evm.nodes.onflow.org"
EXPLORER_API = "https://evm-testnet.flowscan.io/api"
START_TX = "0x58830b21870ebc891d15e469e01f6de78334f1af8c0905fafc63fbd34e726b18"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
visited_txs = set()

PRINTABLE = set(string.printable) - set(string.whitespace) | {' '}

def try_decode(hex_data):
    """Aggressively tries to find any ASCII char in hex data."""
    found_strings = []
    if not hex_data or hex_data == HexBytes('0x'):
        return None
    
    try:

        raw_bytes = bytes.fromhex(hex_data.hex()[2:])
        clean_str = raw_bytes.replace(b'\x00', b'').decode('utf-8', errors='ignore')
        

        filtered_str = "".join([c for c in clean_str if c in PRINTABLE])
        
        if len(filtered_str) > 0:
            return filtered_str
    except:
        pass
    return None

def analyze_tx(tx_hash):
    results = []
    
    try:
        tx = w3.eth.get_transaction(tx_hash)
        input_msg = try_decode(tx['input'])
        if input_msg:
            results.append(f"IN: [{input_msg}]")


        receipt = w3.eth.get_transaction_receipt(tx_hash)
        for log in receipt['logs']:
            # Check Data
            log_msg = try_decode(log['data'])
            if log_msg:
                results.append(f"LOG: [{log_msg}]")
            
            # Check Topics (Indexed params often hold chars)
            for topic in log['topics']:
                topic_msg = try_decode(topic)
                if topic_msg:
                    results.append(f"TOPIC: [{topic_msg}]")
                    
    except Exception as e:
        pass
        
    return " | ".join(results)

def get_outgoing(address, start_block):
    """Get all outgoing transactions after the money was received."""
    try:
        params = {'module': 'account', 'action': 'txlist', 'address': address, 'sort': 'asc'}
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(EXPLORER_API, params=params, headers=headers, timeout=5).json()
        
        valid = []
        if r['status'] == '1' and r['result']:
            for tx in r['result']:
                if tx['from'].lower() == address.lower() and int(tx['blockNumber']) > start_block:
                    valid.append(tx)
        return valid
    except:
        return []

def trace(tx_hash, depth=0):
    indent = "  " * depth
    if tx_hash in visited_txs: return
    visited_txs.add(tx_hash)

    try:
        tx = w3.eth.get_transaction(tx_hash)
        receiver = tx['to']
        block = tx['blockNumber']
    except:
        return

    hidden_data = analyze_tx(tx_hash)
    

    if hidden_data:
        print(f"{indent}> {tx_hash[-4:]} \033[92m{hidden_data}\033[0m")
    else:
        print(f"{indent}> {tx_hash[-4:]}")

    if not receiver: return

    outgoing = get_outgoing(receiver, block)
    for out_tx in outgoing:
        time.sleep(0.1) # Rate limit
        trace(out_tx['hash'], depth + 1)

print("[*] Starting Unfiltered Deep Scan...")
print("[*] Looking for fragments like '{', '}', '_', '1'...")
trace(START_TX)
```
- After running it for few minutes, it went through all the branches and showed me the output in UTF-8 format
<img width="865" height="492" alt="WindowsTerminal_DfeFxijuQ6" src="https://github.com/user-attachments/assets/82a71718-94bd-4962-baa0-056b40ce5eb8" />

