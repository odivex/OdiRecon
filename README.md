# 🔴 OdiRecon – Advanced Red Team Recon Toolkit v1.0

> ⚡ Professional Reconnaissance Framework for Authorized Security Testing
> Coded by **Vaibhav Bhoot**
> Website: [https://vaibhavbhoot.in](https://vaibhavbhoot.in)

---

## 📌 Overview

**OdiRecon** is a modular, multi-threaded reconnaissance toolkit built for **red teamers, bug bounty hunters, and penetration testers**.

It combines DNS enumeration, HTTP probing, port scanning, misconfiguration detection, takeover detection, and more — into a single powerful CLI + interactive framework.

This tool is designed strictly for:

* Authorized security testing
* Bug bounty programs
* Lab environments
* Educational cybersecurity research

---

## 🔥 Core Features

### 🌐 Subdomain Enumeration

* Multi-threaded DNS brute-force
* Randomized resolver selection
* CNAME detection
* Wordlist variation generator

### 🔍 HTTP Probing

* HTTPS + HTTP auto fallback
* Status code detection
* Content length detection
* Redirect handling

### 🔌 Port Scanning

* Scans 25+ common service ports
* Concurrent TCP scanning
* Detects open services

### 🛡 WAF Detection

* Fingerprint-based detection
* Active payload probing
* Detects:

  * Cloudflare
  * AWS WAF
  * Akamai
  * Imperva
  * Sucuri
  * ModSecurity
  * F5 BIG-IP
  * Fortinet
  * Apache / Nginx

### 💀 Subdomain Takeover Detection

* Detects dangling CNAMEs
* Matches provider fingerprints
* Identifies takeover-prone services

### 🔒 SSL / TLS Analysis

* Cipher detection
* Protocol version check
* Expiry analysis
* Outdated TLS version detection

### 📋 Security Header Audit

Checks missing:

* HSTS
* CSP
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

### 🚨 CORS Misconfiguration

* Wildcard origin detection
* Origin reflection detection
* Credential exposure analysis

### 🪣 S3 Bucket Misconfiguration

* Public bucket detection
* Access denied bucket detection
* Common naming brute-force

### ↪ Open Redirect Detection

* Tests common redirect parameters
* Checks Location header reflection

### 📦 HTTP Smuggling Hints

* TE.CL mismatch detection
* Transfer-Encoding + Content-Length behavior analysis

### ☣ HTTP Parameter Pollution

* Duplicate parameter reflection testing

---

## 🧠 Architecture

OdiRecon is built using:

* `requests` for HTTP interactions
* `dnspython` for DNS resolution
* `socket` for raw TCP testing
* `ssl + cryptography` for TLS parsing
* `rich` for advanced UI
* `prompt_toolkit` for interactive mode
* `concurrent.futures` for multi-threading

Each module runs independently and can be selectively enabled.

---

## ⚙ Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/odivex/OdiRecon.git
cd odirecon
```

### 2️⃣ Install Requirements

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If installing manually:

```bash
pip install rich dnspython requests cryptography pyfiglet prompt_toolkit
```

---

## 🚀 Usage

---

## 🔹 Interactive Mode

Run without arguments:

```bash
python odirecon.py
```

Launches full interactive configuration UI:

* Target input
* Wordlist selection
* Thread configuration
* Module selection
* Output format selection

---

## 🔹 CLI Mode

Basic usage:

```bash
python odirecon.py -d example.com -w wordlist.txt
```

---

### Full Syntax

```bash
python odirecon.py -d DOMAIN -w WORDLIST [OPTIONS]
```

---

### 🔧 Available Arguments

| Argument         | Description                      |
| ---------------- | -------------------------------- |
| `-d, --domain`   | Target domain                    |
| `-w, --wordlist` | Path to subdomain wordlist       |
| `-t, --threads`  | Number of threads (default: 30)  |
| `--timeout`      | Request timeout in seconds       |
| `-o, --output`   | Save output file                 |
| `--format`       | txt, json, csv, html             |
| `--modules`      | Select modules (comma-separated) |
| `--variations`   | Generate wordlist variations     |
| `--list-modules` | Show available modules           |

---

## 🎯 Module Selection

Run specific modules:

```bash
python odirecon.py -d example.com -w wordlist.txt --modules dns,http,ssl,headers
```

Available module keys:

```
dns
http
ports
waf
takeover
ssl
headers
cors
s3
redirect
smuggling
pollution
```

---

## 💾 Output Formats

OdiRecon supports:

* TXT
* JSON
* CSV
* HTML (styled report)

Example:

```bash
python odirecon.py -d example.com -w wordlist.txt -o report.html --format html
```

---

## 📊 Example Scan

```bash
python odirecon.py -d example.com \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50 \
    --timeout 10 \
    --modules dns,http,ports,ssl,headers,cors,s3 \
    -o output.json
```

---

## 📈 Scan Flow

1. Load wordlist
2. Generate variations (optional)
3. DNS brute-force
4. HTTP probing
5. Run selected modules
6. Generate findings
7. Output summary + report

---

## 🔐 Security & Legal Disclaimer

This tool is intended for:

* Authorized penetration testing
* Bug bounty programs
* Lab environments

⚠ Running against systems without permission is illegal.

The author is not responsible for misuse.

---

## 🧩 Why OdiRecon?

Unlike basic recon scripts, OdiRecon provides:

* Modular architecture
* Interactive UI
* Professional reporting
* Severity classification
* Parallel scanning engine
* Red-team focused checks
* Clean findings model

It’s not just a script — it’s a **recon framework**.

---

## 🛠 Future Improvements (Optional Roadmap)

* Shodan integration
* WHOIS analysis
* ASN enumeration
* Screenshot capture
* JavaScript endpoint extraction
* Directory fuzzing module
* Proxy support (Burp/ZAP)

---

## 👨‍💻 Author

**Vaibhav Bhoot**
Cybersecurity Researcher | Red Team Enthusiast
Instagram: @vaibhavpatidarbhoot
Website: [https://vaibhavbhoot.in](https://vaibhavbhoot.in)

