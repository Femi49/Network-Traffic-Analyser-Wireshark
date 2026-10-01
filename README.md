# Wireshark Network Analysis: Port Scan to Web Shell

My write-up of the Blue Team Labs Online (BTLO) challenge **Network Analysis – Web Shell**. It's a retired, easy-rated challenge, and I used it to practise reading a real-looking attack chain out of a packet capture using Wireshark.

The scenario is simple. The SOC gets a SIEM alert for "Local to Local Port Scanning": one internal IP starts probing another internal machine. The job is to work out whether it's harmless or malicious. Spoiler: it's malicious, and it doesn't stop at a port scan.

**Short version of what happened:** `10.251.96.4` port scans `10.251.96.5`, brute-forces directories with Gobuster, pokes the login form for SQL injection (by hand first, then with sqlmap), uploads a PHP web shell through the profile page, runs a few commands through it, and then pops a reverse shell back to his own machine.

---

## What's in this repo

```
wireshark-network-analysis/
├── README.md
├── screenshots/
│   ├── 00-challenge/
│   │   └── network-analysis-challenge-page.png
│   ├── 01-capture-overview/
│   │   ├── capture-file-properties.png
│   │   ├── protocol-hierarchy.png
│   │   └── conversations.png
│   ├── 02-baseline-traffic/
│   │   ├── first-get-requests.png
│   │   ├── http-stream-0.png
│   │   ├── login-post-packets.png
│   │   └── login-cleartext-creds.png
│   ├── 03-port-scan/
│   │   ├── scan-syn-packets.png
│   │   ├── scan-rst-responses.png
│   │   ├── syn-ack-filter.png
│   │   └── open-port-22.png
│   ├── 04-directory-bruteforce/
│   │   ├── gobuster-get-requests.png
│   │   ├── large-200-responses.png
│   │   └── response-body-stream.png
│   ├── 05-sql-injection/
│   │   ├── login-single-quote-probe.png
│   │   ├── all-post-requests.png
│   │   └── sqlmap-payload-stream.png
│   ├── 06-web-shell-upload/
│   │   ├── upload-php-packet.png
│   │   └── webshell-stream.png
│   ├── 07-command-execution/
│   │   ├── get-requests-after-upload.png
│   │   └── cmd-id-response.png
│   └── 08-reverse-shell/
│       ├── reverse-shell-payload.png
│       └── reverse-shell-tcp-stream.png
└── notes/
    └── setup.md        (optional: how I unzipped and opened the pcap)
```

The numbered folders follow the order the attack happened in, so you can read the screenshots top to bottom like a timeline.

> **About the pcap:** I haven't committed `BTLOPortScan.pcap` itself. It contains a working web shell and attack traffic, and it belongs to BTLO anyway. You can grab it from the challenge page. To check you have the same file, compare the hash:
> `SHA256: e8ca5bd33178150b770043be59da117253d20a076de7898cab5cdbeef75f109f`

---

## Tools

- Wireshark (display filters, Follow HTTP Stream, Statistics menus)
- Kali Linux for the workspace
- `unzip` for the password-protected download (the challenge page lists the password)

TCPDump and TShark are also listed for the challenge, but I stuck with Wireshark's GUI this time.

---

## The capture at a glance

| Item | Value |
|---|---|
| File | `BTLOPortScan.pcap` (pcapng, about 4.5 MB) |
| Packets | 17,508 |
| Duration | about 15 minutes (908 seconds) |
| Captured on | Linux, interface `any` (cooked-mode capture), Dumpcap 2.6.10 |
| Date | 2021-02-07 |

A couple of things I noticed straight away from the Statistics menus:

- **Protocol Hierarchy:** IPv4 is 99.3% of the traffic, TCP is 98.6%, and HTTP alone is about 56% of all packets. There's a small amount of SSH, DNS, mDNS, DHCP, NetBIOS and ARP in the background.
- **Conversations:** the busiest pair by far is `10.251.96.4` and `10.251.96.5`, roughly 15,900 packets and 4 MB over about 770 seconds. Everything else is small background noise.

One small gotcha: the Time column in the packet list is in UTC (the `Z` at the end), while Capture File Properties shows local time, which is one hour ahead. All the timestamps below are UTC from the packet list.

---

## Who's who

| Role | IP |
|---|---|
| Attacker / scanning host | `10.251.96.4` |
| Target web server (Apache 2.4.29 on Ubuntu) | `10.251.96.5` |

The web server also shows up as `172.20.10.2` in the early traffic, talking to a client at `172.20.10.5`. I'm treating that as the same box seen on a second interface, since the capture was taken on `any`.

---

## Timeline of the attack

All times are UTC, 2021-02-07.

| Time | What happens |
|---|---|
| 16:31:24 | A normal looking client (`172.20.10.5`) browses the site: `GET /`, a 404 for `favicon.ico`, then the login page |
| 16:31:35 | Someone logs in with the admin account. The credentials go over plain HTTP, so they're readable in the capture |
| 16:33:06 | Port scan starts from `10.251.96.4` |
| 16:33:40 | Manual SQL injection test on `login.php` (a single quote in both fields) |
| 16:34:05 | Directory brute-forcing begins (Gobuster) |
| 16:36:51 | sqlmap fires a burst of POST requests in under a second |
| 16:40:39 | PHP web shell uploaded through `/upload.php` |
| 16:40:43 | Attacker browses `/uploads/` and finds the file |
| 16:40:51 | First command through the shell: `?cmd=id`, answered as `www-data` |
| 16:40:56 | `?cmd=whoami` |
| 16:42:35 | Python reverse shell sent through `?cmd=`, connecting back to `10.251.96.4:4422` |

---

## Step by step

### 1. Port scan

Filter I used to find the scan traffic:

```
ip.addr == 10.251.96.5 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

That shows only the SYN-ACK replies, which means only the ports that answered as **open**. From the target I saw replies from **port 80 (HTTP)** and **port 22 (SSH)**. Everything else came back with a RST, ACK, which is the "closed" answer.

A few things point to a classic Nmap-style SYN scan:

- every probe comes from the same source port (`41675`)
- the SYN packets are tiny, with window size 1024 and only an MSS option
- they go out a few microseconds apart, which no human with a browser could do
- the scanner never finishes the handshake on open ports. It answers the SYN-ACK from port 80 with a RST (half-open scanning)
- the ports hit (25, 110, 111, 113, 139, 143, 199, 256, 443, 587, 993, 995 and so on) look like Nmap's usual common-ports list

### 2. Directory brute-forcing

```
ip.addr == 10.251.96.4 && http.request.method == "GET"
```

This gives a long run of GET requests for paths like `/zope`, `/zorum` and `/zt`, arriving a fraction of a millisecond apart. That's a wordlist being thrown at the server, which is what Gobuster does. The scanner also opens a lot of parallel connections from consecutive ephemeral ports, which matches how the tool runs multiple threads.

To spot the requests that actually found something, I filtered for successful, larger responses:

```
ip.addr == 10.251.96.4 && http.response.code == 200 && http.content_length > 1000
```

Only two came back, and following the HTTP stream on the first one shows a page full of table styling. It looks like a PHP info style page, which would be a juicy find for an attacker because it leaks the server configuration.

### 3. SQL injection

Two phases here.

**By hand.** At 16:33:40 there's a POST to `/login.php` with `username=%27&password=%27`. That's just a single quote in each field, the standard "does this break the query?" test.

**With sqlmap.** Later, a flood of POST requests hits the server. Following one of them, the User-Agent gives it away: `sqlmap/1.4.7#stable`. The payload in the URL is the usual sqlmap noise: a boolean test (`AND 1=1`), a `UNION ALL SELECT` pulling from `information_schema.tables`, a stray XSS string, and an attempt to read `/etc/passwd`. Most of that is sqlmap throwing everything at the wall, not a precise attack.

The filter I used to list them all:

```
ip.addr == 10.251.96.5 && http.request.method == POST
```
### Encoded sqlmap input
/?QLuT=8454%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23

### Decoded sqlmap
/?QLuT=8454 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
### 4. Web shell upload

This is the part that turns a noisy scan into an actual compromise. Packet 16102 is a `POST /upload.php` with content type `application/x-php`, coming from the `editprofile.php` page. The uploaded file is called `dbfunctions.php`, which is a nice bit of disguise. It looks like a normal part of the app.

Following the stream shows the contents, and it's a tiny PHP web shell: it checks for a `cmd` parameter in the request and passes whatever it finds straight into `system()`. The server answered `200 OK`.

Two things worth noting:

- The upload uses the **same PHPSESSID cookie** as the earlier login probing, so it was done from an authenticated session.
- The file's content type is `application/x-php`, so the upload form clearly wasn't checking file types.

### 5. Using the web shell

Uploading the file is one thing, but did the attacker actually use it? Yes. Right after the upload the same host starts requesting things out of `/uploads/`:

```
ip.src == 10.251.96.4 && http.request.uri contains "uploads"
```

The order of requests tells the story:

- `GET /uploads/` at 16:40:43. This is Apache's plain directory listing, which is why a couple of `/icons/*.gif` requests show up next to it. The attacker is checking the file landed.
- `GET /uploads/dbfunctions.php` at 16:40:45, with no command, just checking that it responds.
- `GET /uploads/dbfunctions.php?cmd=id` at 16:40:51. Following that stream, the server answers `200 OK` with `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. So the shell works and commands run as the web server user.
- `GET /uploads/dbfunctions.php?cmd=whoami` at 16:40:56, same idea.

The `<pre>` wrapper in the response is the same one from the shell's source code in the upload, which is a nice confirmation that it's the uploaded file answering.

### 6. Reverse shell

At 16:42:35 there's a much longer `cmd=` request. URL-decoded, it's a Python one-liner that:

1. imports `socket`, `subprocess` and `os`
2. opens a TCP connection to **`10.251.96.4` on port `4422`**
3. uses `dup2` to wire stdin, stdout and stderr to that socket
4. starts `/bin/sh -i`

In other words, the web server calls back out to the attacker's machine and hands over an interactive shell. When I followed that HTTP stream it was one client packet and no response at all. That makes sense, because the request never finishes: the shell takes over the process.

The shell session itself is its own TCP conversation, so you can pull it up on its own (it was stream 1277 for me):

```
ip.addr == 10.251.96.5 && tcp.port == 4422
```

Following that stream, you can read the attacker's session almost like a terminal:

- the prompt is `www-data@bob-appserver:/var/www$`, so we now know the hostname of the victim: **bob-appserver**
- `ls` shows a single `html` folder
- `cd ../..` to jump to the filesystem root
- `python -c 'import pty;pty.spawn("/bin/bash")'` to upgrade to a proper interactive terminal. This is a standard step after catching a basic shell
- `bash -i`, then `ls` again, showing the usual root directory (`bin`, `etc`, `home`, `root`, `var` and so on)

Later in the stream, some commands show up with doubled letters (`l l s s`, `c c d d`). That's just the terminal echoing keystrokes back after the upgrade, nothing weird.

At this point it's no longer a "suspicious scan". The attacker has an interactive shell on a production-looking server.

---

## Useful Wireshark filters from this analysis

```
ip.addr == 10.251.96.5 && tcp.flags.syn == 1 && tcp.flags.ack == 1
ip.addr == 10.251.96.4 && http.request.method == "GET"
ip.addr == 10.251.96.4 && http.response.code == 200 && http.content_length > 1000
ip.addr == 10.251.96.5 && http.request.method == POST
ip.src == 10.251.96.4 && http.request.uri contains "cmd="
ip.addr == 10.251.96.5 && tcp.port == 4422
```

Menus I leaned on: **Statistics → Capture File Properties**, **Protocol Hierarchy**, **Conversations**, and **right click → Follow → HTTP Stream**.

---

## What I'd flag to a SOC

- The scanning host (`10.251.96.4`) should be isolated and investigated. This isn't just a vulnerability scan, it ends in a successful upload.
- `dbfunctions.php` needs to be found and removed from the web server, and the box should be treated as compromised.
- Login credentials are being sent over plain HTTP. Move the app to HTTPS.
- The upload form needs real validation (allowed extensions, content checks, and no execution in the upload directory).
- The login form is open to SQL injection. Use parameterised queries.
- A SIEM rule for bursts of requests with the sqlmap User-Agent would have caught this much earlier.
- Alert on any request to `/uploads/*.php`. Uploaded files should never be executable.
- The web server opening an outbound connection to an internal workstation on an odd port (4422) is a strong reverse shell signal. Egress filtering on the web server would have blocked it.
- Check `bob-appserver` for anything the attacker did as `www-data`, and review which accounts and files that user can reach.

## Still to dig into

I haven't gone through everything in the capture. Things I want to check next:

- the rest of the reverse shell session (I've only looked at the first screen of stream 1277, so there may be more commands further down)
- the exact port range the scan covered
- the SSH traffic on port 22, to see if anything came of it

---

## Credits

Challenge by [Blue Team Labs Online](https://blueteamlabs.online/). Write-up and screenshots are mine. This was done in a lab environment on a public training challenge.
