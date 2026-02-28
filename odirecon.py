#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║     OdiRecon | Advanced Red Team Recon Toolkit v1.0       ║
║      Coded by: Vaibhav Bhoot | @vaibhavpatidarbhoot       ║
╚═══════════════════════════════════════════════════════════╝
"""

import socket
import concurrent.futures
import argparse
import sys
import time
import random
import json
import csv
import os
import ssl
import re
import warnings
from datetime import datetime
from urllib.parse import urlparse, urlencode, urljoin

# ── Suppress SSL warnings ────────────────────────────────────────────────────
warnings.filterwarnings("ignore")
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ── Rich ─────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.style import Style
    from rich import box
    from rich.columns import Columns
    from rich.markup import escape
    RICH = True
except ImportError:
    RICH = False
    print("[!] Install rich: pip install rich")
    sys.exit(1)

# ── Pyfiglet ─────────────────────────────────────────────────────────────────
try:
    import pyfiglet
    FIGLET = True
except ImportError:
    FIGLET = False

# ── Prompt Toolkit ───────────────────────────────────────────────────────────
try:
    from prompt_toolkit import prompt
    from prompt_toolkit.styles import Style as PTStyle
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.shortcuts import checkboxlist_dialog, radiolist_dialog, input_dialog, message_dialog
    from prompt_toolkit.validation import Validator, ValidationError
    from prompt_toolkit.completion import WordCompleter
    PROMPT_TOOLKIT = True
except ImportError:
    PROMPT_TOOLKIT = False

# ── DNS / Requests ───────────────────────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] Install dnspython: pip install dnspython")
    sys.exit(1)

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Install requests: pip install requests")
    sys.exit(1)

# ── Cryptography (SSL cert parsing) ──────────────────────────────────────────
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO = True
except ImportError:
    CRYPTO = False

# ─────────────────────────────────────────────────────────────────────────────
console = Console()

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold bright_red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "bold green",
}

TOOL_VERSION = "1.0"
AUTHOR       = "Vaibhav Bhoot"
WEBSITE       = "https://vaibhavbhoot.in"
INSTAGRAM    = "@vaibhavpatidarbhoot"

# ── Known subdomain takeover fingerprints ────────────────────────────────────
TAKEOVER_FINGERPRINTS = {
    "amazonaws.com":           "NoSuchBucket",
    "github.io":               "There isn't a GitHub Pages site here",
    "herokuapp.com":           "No such app",
    "azurewebsites.net":       "The specified resource does not exist",
    "cloudfront.net":          "ERROR: The request could not be satisfied",
    "fastly.net":              "Fastly error: unknown domain",
    "shopify.com":             "Sorry, this shop is currently unavailable",
    "surge.sh":                "project not found",
    "bitbucket.io":            "Repository not found",
    "ghost.io":                "The thing you were looking for is no longer here",
    "pantheon.io":             "The gods are wise, but do not know of the site",
    "zendesk.com":             "Help Center Closed",
    "freshdesk.com":           "There is no helpdesk here",
    "readme.io":               "Project doesnt exist",
    "airee.ru":                "Ошибка",
    "cargo.site":              "404 Not Found",
    "launchrock.com":          "It looks like you may have taken a wrong turn",
    "feedpress.me":            "The feed has not been found",
    "unbounce.com":            "The requested URL was not found on this server",
    "smugmug.com":             "Page Not Found",
    "tumblr.com":              "There's nothing here",
}

# ── Common security headers ───────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security":       ("HSTS missing",       "HIGH"),
    "Content-Security-Policy":         ("CSP missing",        "HIGH"),
    "X-Frame-Options":                 ("Clickjacking risk",  "MEDIUM"),
    "X-Content-Type-Options":          ("MIME sniff risk",    "MEDIUM"),
    "Referrer-Policy":                 ("Referrer leak risk", "LOW"),
    "Permissions-Policy":              ("Permissions Policy missing", "LOW"),
    "X-XSS-Protection":                ("XSS filter missing", "LOW"),
    "Cache-Control":                   ("Cache control missing", "INFO"),
}

# ── Common open-redirect params ───────────────────────────────────────────────
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "next", "dest", "destination", "goto", "link",
    "to", "out", "view", "from", "target", "site", "page",
]

# ── Common ports ──────────────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 465, 587, 993, 995, 3306, 3389, 5432, 6379,
                 8080, 8443, 8888, 9200, 27017]

# ── WAF fingerprints ─────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare":      ["cf-ray", "cloudflare"],
    "AWS WAF":         ["awselb", "x-amzn-requestid"],
    "Akamai":          ["akamai", "ak-bmsc"],
    "Sucuri":          ["x-sucuri-id", "sucuri"],
    "Imperva":         ["x-iinfo", "incapsula"],
    "ModSecurity":     ["mod_security", "modsecurity"],
    "Barracuda":       ["barra", "bnmobileweb"],
    "F5 BIG-IP":       ["bigip", "x-cnection"],
    "Fortinet":        ["fortigate", "fortiproxy"],
    "Nginx":           ["nginx"],
    "Apache":          ["apache"],
}

DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.8.4.4"]
DEFAULT_UA    = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

# Gradient colors for banner lines (red → orange → yellow)
_GRAD = [
    "bold bright_red", "bold bright_red", "bold red",
    "bold dark_orange", "bold yellow", "bold bright_yellow",
]

def _gradient_figlet(text: str, font: str = "slant") -> None:
    fig = pyfiglet.figlet_format(text, font=font)
    lines = fig.splitlines()
    colors = _GRAD

    for i, line in enumerate(lines):
        color = colors[min(i, len(colors) - 1)]
        console.print(f"[{color}]{escape(line)}[/{color}]")

def _type_print(text: str, style: str = "bold green", delay: float = 0.018) -> None:
    """Simulate typing effect for a single line."""
    import shutil
    for ch in text:
        console.print(f"[{style}]{ch}[/{style}]", end="", highlight=False)
        time.sleep(delay)
    console.print()

def print_banner():
    console.clear()
    if FIGLET:
        _gradient_figlet("OdiRecon", font="slant")
    else:
        console.print("[bold bright_red]★  RED RECON TOOLKIT  ★[/bold bright_red]")

    # Glowing separator
    sep = Text()
    colors = ["red", "bright_red", "dark_orange", "yellow", "bright_yellow",
               "yellow", "dark_orange", "bright_red", "red"]
    chunk = "━" * 9
    for c in colors:
        sep.append(chunk, style=f"bold {c}")
    console.print(sep, justify="center")
    console.print()

    # Info Table
    info = Table.grid(padding=(0, 3))
    info.add_column(style="bold bright_red")
    info.add_column(style="bold white")
    info.add_row("◈  Version",    f"[bold cyan]{TOOL_VERSION}[/bold cyan]")
    info.add_row("◈  Author",     f"[bold yellow]{AUTHOR}[/bold yellow]")
    info.add_row("◈  WEBSITE",     f"[bold green]{WEBSITE}[/bold green]")
    info.add_row("◈  Instagram",  f"[bold magenta]{INSTAGRAM}[/bold magenta]")

    console.print(Panel(
        info,
        title=" [bold bright_red]⚡[/bold bright_red] [bold yellow]Advanced Red Team Recon Toolkit[/bold yellow] [bold bright_red]⚡[/bold bright_red] ",
        subtitle=" [dim]Use responsibly · For authorized targets only[/dim] ",
        border_style="bright_red",
        padding=(1, 4),
        expand=False,
    ))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# FINDING MODEL
# ─────────────────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, module: str, title: str, severity: str, target: str, detail: str = ""):
        self.module   = module
        self.title    = title
        self.severity = severity.upper()
        self.target   = target
        self.detail   = detail
        self.ts       = datetime.now().isoformat()

    def to_dict(self):
        return {
            "module":    self.module,
            "title":     self.title,
            "severity":  self.severity,
            "target":    self.target,
            "detail":    self.detail,
            "timestamp": self.ts,
        }

    def log(self):
        style = SEVERITY_STYLE.get(self.severity, "white")
        sev   = f"[{style}][{self.severity}][/{style}]"
        console.print(
            f"  {sev} [{escape(self.module)}] {escape(self.title)} — {escape(self.target)}"
            + (f"\n       [dim]{escape(self.detail)}[/dim]" if self.detail else "")
        )


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class OdiReconScanner:
    def __init__(self, domain: str, threads: int = 30,
                 timeout: int = 5, user_agent: str = DEFAULT_UA):
        self.domain     = domain.strip().lower()
        self.threads    = threads
        self.timeout    = timeout
        self.ua         = user_agent
        self.session    = self._build_session()
        self.findings: list[Finding] = []
        self.live_hosts: list[dict]  = []
        self.stats = {
            "scanned":    0,
            "live":       0,
            "start_time": None,
            "end_time":   None,
        }

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": self.ua,
            "Accept":     "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        return s

    def _get(self, url: str, **kwargs) -> requests.Response | None:
        try:
            return self.session.get(
                url, timeout=self.timeout, verify=False,
                allow_redirects=True, **kwargs
            )
        except Exception:
            return None

    def _add(self, module, title, severity, target, detail=""):
        f = Finding(module, title, severity, target, detail)
        f.log()
        self.findings.append(f)

    # ── DNS helpers ──────────────────────────────────────────────────────────

    def _resolve(self, hostname: str, rtype="A") -> list[str]:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [random.choice(DNS_RESOLVERS)]
            r.timeout = self.timeout
            r.lifetime = self.timeout
            return [str(a) for a in r.resolve(hostname, rtype)]
        except Exception:
            return []

    def _cname(self, hostname: str) -> str | None:
        try:
            r = dns.resolver.Resolver()
            r.timeout = self.timeout
            return str(r.resolve(hostname, "CNAME")[0].target)
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 1 — DNS Subdomain Enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_dns_single(self, sub: str) -> dict | None:
        fqdn = f"{sub}.{self.domain}"
        self.stats["scanned"] += 1
        ips = self._resolve(fqdn)
        if not ips:
            return None
        cname = self._cname(fqdn)
        result = {
            "subdomain": fqdn,
            "ips":       ips,
            "cname":     cname,
            "type":      "DNS",
        }
        self.stats["live"] += 1
        self._add("DNS", "Live subdomain", "INFO", fqdn,
                  f"IPs: {', '.join(ips)}" + (f" | CNAME: {cname}" if cname else ""))
        return result

    def run_dns_enum(self, wordlist: list[str], progress=None, task_id=None) -> list[dict]:
        console.rule("[bold yellow]DNS Subdomain Enumeration[/bold yellow]")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_dns_single, s): s for s in wordlist}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)
                if progress and task_id is not None:
                    progress.advance(task_id)
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 2 — HTTP Probing
    # ─────────────────────────────────────────────────────────────────────────

    def _probe_http_single(self, host: dict) -> dict | None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host['subdomain']}"
            r   = self._get(url)
            if r is not None:
                host["http_url"]     = url
                host["status_code"]  = r.status_code
                host["content_len"]  = len(r.content)
                host["http_headers"] = dict(r.headers)
                host["final_url"]    = r.url
                self._add("HTTP", "HTTP live", "INFO", url,
                          f"Status: {r.status_code}  Size: {len(r.content)}")
                return host
        return None

    def run_http_probe(self, hosts: list[dict]) -> list[dict]:
        console.rule("[bold yellow]HTTP Probing[/bold yellow]")
        live = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._probe_http_single, h): h for h in hosts}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    live.append(r)
        return live

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 3 — Port Scanner
    # ─────────────────────────────────────────────────────────────────────────

    def _scan_port(self, ip: str, port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.2)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    def run_port_scan(self, hosts: list[dict]):
        console.rule("[bold yellow]Port Scanner[/bold yellow]")
        reported = set()
        for host in hosts:
            for ip in host.get("ips", []):
                if ip in reported:
                    continue
                reported.add(ip)
                open_ports = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                    futs = {ex.submit(self._scan_port, ip, p): p for p in COMMON_PORTS}
                    for fut in concurrent.futures.as_completed(futs):
                        p = fut.result()
                        if p:
                            open_ports.append(p)
                if open_ports:
                    open_ports.sort()
                    self._add("Ports", "Open ports found", "INFO", ip,
                              f"Ports: {', '.join(map(str, open_ports))}")
                    host["open_ports"] = open_ports

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 4 — WAF Detection
    # ─────────────────────────────────────────────────────────────────────────

    def run_waf_detection(self, hosts: list[dict]):
        console.rule("[bold yellow]WAF Detection[/bold yellow]")
        for host in hosts:
            url = host.get("http_url")
            if not url:
                continue
            hdrs = host.get("http_headers", {})
            raw  = " ".join(f"{k} {v}" for k, v in hdrs.items()).lower()
            detected = []
            for waf, sigs in WAF_SIGNATURES.items():
                if any(s in raw for s in sigs):
                    detected.append(waf)
            # Probe with a malicious payload to trigger WAF
            probe_url = url + "/?a=<script>alert(1)</script>"
            resp = self._get(probe_url)
            if resp and resp.status_code in (403, 406, 429, 501):
                detected.append("Unknown WAF (blocked probe)")
            if detected:
                self._add("WAF", "WAF detected", "INFO",
                          host["subdomain"], f"Detected: {', '.join(set(detected))}")
            else:
                console.print(f"  [dim]No WAF detected on {host['subdomain']}[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 5 — Subdomain Takeover
    # ─────────────────────────────────────────────────────────────────────────

    def run_takeover_check(self, hosts: list[dict]):
        console.rule("[bold yellow]Subdomain Takeover Check[/bold yellow]")
        for host in hosts:
            fqdn  = host.get("subdomain", "")
            cname = host.get("cname") or self._cname(fqdn) or ""
            for provider, fp in TAKEOVER_FINGERPRINTS.items():
                if provider in cname.lower():
                    # Try HTTP to confirm fingerprint
                    r = self._get(f"http://{fqdn}")
                    if r and fp.lower() in r.text.lower():
                        self._add("Takeover", "Subdomain takeover possible", "HIGH",
                                  fqdn, f"CNAME → {cname} | Provider: {provider}")
                    else:
                        self._add("Takeover", "Dangling CNAME (potential takeover)", "MEDIUM",
                                  fqdn, f"CNAME → {cname} | Provider: {provider}")
                    break

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 6 — SSL / TLS Info
    # ─────────────────────────────────────────────────────────────────────────

    def _ssl_info(self, hostname: str) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=self.timeout),
                server_hostname=hostname
            ) as s:
                cert_bin = s.getpeercert(binary_form=True)
                cipher   = s.cipher()
                info = {"cipher": cipher[0], "protocol": cipher[1],
                        "host": hostname, "bits": cipher[2]}
                if CRYPTO and cert_bin:
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    info["subject"]   = cert.subject.rfc4514_string()
                    info["issuer"]    = cert.issuer.rfc4514_string()
                    info["not_after"] = cert.not_valid_after_utc.isoformat()
                    days_left = (cert.not_valid_after_utc - datetime.now(
                        cert.not_valid_after_utc.tzinfo)).days
                    info["days_left"] = days_left
                return info
        except Exception:
            return None

    def run_ssl_check(self, hosts: list[dict]):
        console.rule("[bold yellow]SSL / TLS Info[/bold yellow]")
        for host in hosts:
            fqdn = host.get("subdomain", "")
            info = self._ssl_info(fqdn)
            if not info:
                continue
            detail = f"Cipher: {info['cipher']} | Protocol: {info['protocol']} | Bits: {info['bits']}"
            if "days_left" in info:
                detail += f" | Expiry: {info['not_after']} ({info['days_left']}d left)"
            sev = "HIGH" if info.get("days_left", 999) < 15 else "INFO"
            self._add("SSL", "SSL/TLS info", sev, fqdn, detail)
            if info.get("protocol") in ("TLSv1", "TLSv1.1"):
                self._add("SSL", "Outdated TLS version", "MEDIUM", fqdn,
                          f"Protocol in use: {info['protocol']}")

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 7 — Security Headers Audit
    # ─────────────────────────────────────────────────────────────────────────

    def run_security_headers(self, hosts: list[dict]):
        console.rule("[bold yellow]Security Headers Audit[/bold yellow]")
        for host in hosts:
            hdrs = {k.lower(): v for k, v in host.get("http_headers", {}).items()}
            url  = host.get("http_url", host.get("subdomain"))
            for header, (desc, sev) in SECURITY_HEADERS.items():
                if header.lower() not in hdrs:
                    self._add("Headers", desc, sev, url)

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 8 — CORS Misconfiguration
    # ─────────────────────────────────────────────────────────────────────────

    def run_cors_check(self, hosts: list[dict]):
        console.rule("[bold yellow]CORS Misconfiguration[/bold yellow]")
        for host in hosts:
            url = host.get("http_url")
            if not url:
                continue
            # Reflect evil origin
            evil = "https://evil.attacker.com"
            try:
                r = self.session.get(
                    url, timeout=self.timeout, verify=False,
                    headers={"Origin": evil}
                )
            except Exception:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                self._add("CORS", "Wildcard CORS", "MEDIUM",
                          url, "Access-Control-Allow-Origin: *")
            elif evil in acao:
                detail = f"Reflects evil origin | Credentials: {acac}"
                sev    = "HIGH" if acac.lower() == "true" else "MEDIUM"
                self._add("CORS", "CORS origin reflection", sev, url, detail)

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 9 — S3 Bucket Check
    # ─────────────────────────────────────────────────────────────────────────

    def run_s3_check(self):
        console.rule("[bold yellow]S3 Bucket Misconfiguration[/bold yellow]")
        base   = self.domain.replace(".", "-")
        names  = [
            base, f"{base}-backup", f"{base}-dev", f"{base}-staging",
            f"{base}-prod", f"{base}-assets", f"{base}-static",
            f"{base}-media", f"{base}-uploads", f"{base}-data",
            f"dev-{base}", f"staging-{base}", f"backup-{base}",
        ]
        found = 0
        for name in names:
            url = f"https://{name}.s3.amazonaws.com"
            r = self._get(url)
            if r is None:
                continue
            if r.status_code == 200:
                self._add("S3", "Public S3 bucket", "CRITICAL", url,
                          "Bucket is publicly accessible / listing enabled")
                found += 1
            elif r.status_code == 403:
                self._add("S3", "S3 bucket exists (access denied)", "MEDIUM", url,
                          "Bucket exists but is private — still interesting")
                found += 1
        if found == 0:
            console.print("  [dim]No obvious S3 buckets found[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 10 — Open Redirect
    # ─────────────────────────────────────────────────────────────────────────

    def run_open_redirect(self, hosts: list[dict]):
        console.rule("[bold yellow]Open Redirect Check[/bold yellow]")
        payload = "https://evil.attacker.com"
        for host in hosts:
            url = host.get("http_url")
            if not url:
                continue
            found = False
            for param in REDIRECT_PARAMS:
                test_url = f"{url}/?{param}={payload}"
                try:
                    r = self.session.get(
                        test_url, timeout=self.timeout, verify=False,
                        allow_redirects=False,
                        headers={"User-Agent": self.ua}
                    )
                    loc = r.headers.get("Location", "")
                    if payload in loc or "evil.attacker.com" in loc:
                        self._add("Redirect", "Open redirect found", "MEDIUM",
                                  test_url, f"Location: {loc}")
                        found = True
                        break
                except Exception:
                    pass
            if not found:
                console.print(f"  [dim]No open redirect on {host['subdomain']}[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 11 — HTTP Smuggling Hints
    # ─────────────────────────────────────────────────────────────────────────

    def run_http_smuggling(self, hosts: list[dict]):
        console.rule("[bold yellow]HTTP Smuggling Hints[/bold yellow]")
        for host in hosts:
            url = host.get("http_url")
            if not url:
                continue
            # TE.CL hint — send chunked + CL mismatch
            parsed = urlparse(url)
            target = parsed.netloc
            try:
                raw = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Length: 4\r\n\r\n"
                    f"0\r\n\r\n"
                )
                with socket.create_connection(
                    (parsed.hostname, 443 if parsed.scheme == "https" else 80),
                    timeout=self.timeout
                ) as sock:
                    if parsed.scheme == "https":
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=parsed.hostname)
                    sock.sendall(raw.encode())
                    resp = sock.recv(4096).decode("utf-8", errors="ignore")
                    if "Transfer-Encoding" in resp and "Content-Length" in resp:
                        self._add("Smuggling", "Possible HTTP smuggling (TE+CL both accepted)",
                                  "HIGH", url,
                                  "Server accepts both Transfer-Encoding and Content-Length")
                    elif resp:
                        console.print(f"  [dim]No obvious smuggling indicators on {host['subdomain']}[/dim]")
            except Exception:
                console.print(f"  [dim]Could not test smuggling on {host['subdomain']}[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 12 — Parameter Pollution
    # ─────────────────────────────────────────────────────────────────────────

    def run_param_pollution(self, hosts: list[dict]):
        console.rule("[bold yellow]Parameter Pollution[/bold yellow]")
        for host in hosts:
            url = host.get("http_url")
            if not url:
                continue
            # Duplicate common params
            test_url = f"{url}/?id=1&id=2&user=test&user=evil"
            r = self._get(test_url)
            if r and r.status_code == 200:
                text = r.text.lower()
                if "evil" in text:
                    self._add("HPP", "HTTP Parameter Pollution reflected", "LOW",
                              test_url, "Server reflected duplicated param value")
                else:
                    console.print(f"  [dim]No HPP reflection on {host['subdomain']}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            words = [l.strip() for l in f if l.strip()]
        console.print(f"  [bold green][+][/bold green] Loaded [cyan]{len(words):,}[/cyan] words from [dim]{path}[/dim]")
        return words
    except FileNotFoundError:
        console.print(f"  [bold red][!] Wordlist not found: {path}[/bold red]")
        sys.exit(1)


def generate_variations(base: list[str]) -> list[str]:
    variations = set(base)
    prefixes = ["dev", "staging", "prod", "api", "admin", "test", "beta", "portal"]
    suffixes = ["-dev", "-api", "-test", "-admin", "-old", "-backup", "-prod"]
    for w in base:
        for p in prefixes:
            variations.add(f"{p}-{w}")
        for s in suffixes:
            variations.add(f"{w}{s}")
    return list(variations)


def print_summary(scanner: OdiReconScanner):
    console.print()
    console.rule("[bold red]SCAN SUMMARY[/bold red]")
    dur = (scanner.stats["end_time"] - scanner.stats["start_time"])

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="cyan bold")
    meta.add_column(style="white")
    meta.add_row("Domain",         scanner.domain)
    meta.add_row("Subdomains tried", f"{scanner.stats['scanned']:,}")
    meta.add_row("Live found",      f"{scanner.stats['live']:,}")
    meta.add_row("Findings",        f"{len(scanner.findings):,}")
    meta.add_row("Duration",        f"{dur:.2f}s")
    meta.add_row("Threads",         str(scanner.threads))
    console.print(Panel(meta, title="[bold yellow]Stats[/bold yellow]", border_style="yellow"))

    if not scanner.findings:
        console.print("[dim]No findings.[/dim]")
        return

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    table = Table(
        title="Findings",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_black",
    )
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Module",   width=12)
    table.add_column("Title",    width=40)
    table.add_column("Target",   width=40, overflow="fold")
    table.add_column("Detail",   overflow="fold")

    for sev in sev_order:
        for f in scanner.findings:
            if f.severity == sev:
                style = SEVERITY_STYLE.get(sev, "white")
                table.add_row(
                    f"[{style}]{sev}[/{style}]",
                    f.module, f.title, f.target, f.detail
                )
    console.print(table)


def save_results(findings: list[Finding], path: str, fmt: str):
    data = [f.to_dict() for f in findings]
    try:
        if fmt == "json":
            with open(path, "w") as fp:
                json.dump(data, fp, indent=2)

        elif fmt == "csv":
            with open(path, "w", newline="") as fp:
                w = csv.DictWriter(fp, fieldnames=data[0].keys() if data else [])
                w.writeheader()
                w.writerows(data)

        elif fmt == "html":
            rows = ""
            for d in data:
                rows += (
                    f"<tr>"
                    f"<td>{d['severity']}</td><td>{d['module']}</td>"
                    f"<td>{d['title']}</td><td>{d['target']}</td>"
                    f"<td>{d['detail']}</td><td>{d['timestamp']}</td>"
                    f"</tr>\n"
                )
            html = f"""<!DOCTYPE html><html><head>
<title>OdiRecon Report - {findings[0].target if findings else ''}</title>
<style>
body{{font-family:monospace;background:#0d0d0d;color:#e0e0e0}}
table{{width:100%;border-collapse:collapse}}
th{{background:#222;padding:8px;text-align:left}}
td{{padding:6px;border-bottom:1px solid #333}}
tr:hover{{background:#1a1a1a}}
.CRITICAL{{color:#ff2222;font-weight:bold}}
.HIGH{{color:#ff6600;font-weight:bold}}
.MEDIUM{{color:#ffcc00}}
.LOW{{color:#00ccff}}
.INFO{{color:#00ff88}}
h1{{color:#ff2222}}
</style>
</head><body>
<h1>⚡ OdiRecon Report</h1>
<p>Generated: {datetime.now().isoformat()}</p>
<table>
<tr><th>Severity</th><th>Module</th><th>Title</th><th>Target</th><th>Detail</th><th>Timestamp</th></tr>
{rows}
</table></body></html>"""
            with open(path, "w") as fp:
                fp.write(html)

        else:  # txt
            with open(path, "w") as fp:
                for d in data:
                    fp.write(f"[{d['severity']}] [{d['module']}] {d['title']} — {d['target']}\n")
                    if d["detail"]:
                        fp.write(f"  {d['detail']}\n")

        console.print(f"\n  [bold green][+][/bold green] Results saved → [cyan]{path}[/cyan] ([dim]{fmt.upper()}[/dim])")
    except Exception as e:
        console.print(f"  [red][!] Save failed: {e}[/red]")


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MODE  (prompt_toolkit)
# ─────────────────────────────────────────────────────────────────────────────

ALL_MODULES = [
    ("dns",       "Subdomain DNS Enumeration",  "🌐", "INFO"),
    ("http",      "HTTP Probing",               "🔍", "INFO"),
    ("ports",     "Port Scanner",               "🔌", "INFO"),
    ("waf",       "WAF Detection",              "🛡️",  "INFO"),
    ("takeover",  "Subdomain Takeover Check",   "💀", "HIGH"),
    ("ssl",       "SSL/TLS Info",               "🔒", "INFO"),
    ("headers",   "Security Headers Audit",     "📋", "HIGH"),
    ("cors",      "CORS Misconfiguration",      "🚨", "HIGH"),
    ("s3",        "S3 Bucket Check",            "🪣", "CRITICAL"),
    ("redirect",  "Open Redirect",              "↪️",  "MEDIUM"),
    ("smuggling", "HTTP Smuggling Hints",       "📦", "HIGH"),
    ("pollution", "Parameter Pollution",        "☣️",  "LOW"),
]

# Severity → color for module menu
_SEV_COLOR = {
    "CRITICAL": "bold bright_red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "bold green",
}

PT_STYLE = PTStyle.from_dict({
    "prompt":        "bold ansired",
    "input":         "ansibrightgreen",
    "placeholder":   "ansidarkgray",
})


class DomainValidator(Validator):
    def validate(self, document):
        text = document.text.strip()
        if not text or "." not in text:
            raise ValidationError(message="⚠  Enter a valid domain (e.g. example.com)")


class IntValidator(Validator):
    def validate(self, document):
        try:
            int(document.text)
        except ValueError:
            raise ValidationError(message="⚠  Must be an integer")


def _section_header(title: str) -> None:
    """Print a vivid colored section header."""
    console.print()
    console.rule(f"[bold bright_red]  {title}  [/bold bright_red]", style="red")


def _ask(prompt_text: str, default: str = "",
         validator=None, completer=None) -> str:
    """Styled prompt_toolkit input field."""
    return prompt(
        HTML(f'<prompt>  <b>⟫</b> </prompt><label>{prompt_text}</label><prompt>: </prompt>'),
        default=default,
        style=PTStyle.from_dict({
            "prompt": "bold ansired",
            "label":  "ansibrightcyan bold",
        }),
        validator=validator,
        validate_while_typing=False,
        completer=completer,
    ).strip()


def interactive_mode() -> dict:
    """Launch interactive hacker-aesthetic prompt_toolkit UI."""
    console.print(Panel(
        Text.assemble(
            ("  INTERACTIVE MODE  ", "bold bright_red on red"),
            "  ",
            ("Enter your target details below. ", "bold white"),
            ("Ctrl+C", "bold yellow"),
            (" to abort at any time.", "white"),
        ),
        border_style="bright_red",
        padding=(0, 2),
    ))
    console.print()

    # ── Target & Wordlist ───────────────────────────────────────────────────
    _section_header("🎯  TARGET CONFIGURATION")
    target   = _ask("Target domain", validator=DomainValidator())
    wordlist = _ask(
        "Wordlist path",
        default="/usr/share/wordlists/dirb/small.txt",
        completer=WordCompleter(
            [
                "/usr/share/wordlists/dirb/small.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/seclists/Discovery/DNS/namelist.txt",
                "./wordlist.txt",
            ],
            match_middle=True,
        ),
    )

    # ── Performance ─────────────────────────────────────────────────────────
    _section_header("⚙️   PERFORMANCE")
    threads = int(_ask("Threads",      default="30", validator=IntValidator()))
    timeout = int(_ask("Timeout (sec)", default="5",  validator=IntValidator()))
    var_raw  = _ask("Generate wordlist variations? [y/n]", default="n")
    variations = var_raw.lower() == "y"

    # ── Output ──────────────────────────────────────────────────────────────
    _section_header("💾  OUTPUT")
    output  = _ask("Output file (leave blank to skip)",  default="")
    fmt_raw = _ask("Format [txt | json | csv | html]",   default="json")
    fmt     = fmt_raw.lower() if fmt_raw.lower() in ("txt", "json", "csv", "html") else "json"

    # ── Module Selector ─────────────────────────────────────────────────────
    _section_header("🔧  SELECT MODULES")
    console.print()

    mod_table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_black",
        padding=(0, 2),
    )
    mod_table.add_column("#",       justify="right",  style="bold bright_red",   width=4)
    mod_table.add_column("Icon",    justify="center",                            width=4)
    mod_table.add_column("Module",  style="bold white",                          width=30)
    mod_table.add_column("Severity", justify="center",                           width=12)

    for i, (key, name, icon, sev) in enumerate(ALL_MODULES, 1):
        sev_style = _SEV_COLOR.get(sev, "white")
        mod_table.add_row(
            str(i),
            icon,
            name,
            f"[{sev_style}]{sev}[/{sev_style}]",
        )

    console.print(mod_table)
    console.print()
    console.print("  [dim]Enter numbers separated by commas, or type [bold]all[/bold] for everything[/dim]")
    console.print()

    sel_raw = _ask("Modules [all / 1,2,3 / ...]", default="all")
    if sel_raw.strip().lower() == "all":
        modules = [k for k, _, __, ___ in ALL_MODULES]
    else:
        idxs = [int(x.strip()) - 1 for x in sel_raw.split(",") if x.strip().isdigit()]
        modules = [ALL_MODULES[i][0] for i in idxs if 0 <= i < len(ALL_MODULES)]
        if not modules:
            modules = [k for k, _, __, ___ in ALL_MODULES]

    # ── Config Preview ──────────────────────────────────────────────────────
    console.print()
    cfg_grid = Table.grid(padding=(0, 3))
    cfg_grid.add_column(style="bold bright_red")
    cfg_grid.add_column(style="bright_white")
    cfg_grid.add_row("Target  ",   f"[bold bright_yellow]{target}[/bold bright_yellow]")
    cfg_grid.add_row("Wordlist",   f"[dim]{wordlist}[/dim]")
    cfg_grid.add_row("Threads ",   f"[cyan]{threads}[/cyan]")
    cfg_grid.add_row("Timeout ",   f"[cyan]{timeout}s[/cyan]")
    cfg_grid.add_row("Output  ",   f"[green]{output or '(none)'}[/green]  [dim]{fmt.upper()}[/dim]")
    cfg_grid.add_row("Modules ",   f"[bright_red]{', '.join(modules)}[/bright_red]")

    console.print(Panel(
        cfg_grid,
        title=" [bold yellow]⚡ SCAN CONFIGURATION ⚡[/bold yellow] ",
        border_style="yellow",
        padding=(1, 3),
        expand=False,
    ))
    console.print()

    return {
        "domain":     target,
        "wordlist":   wordlist,
        "threads":    threads,
        "timeout":    timeout,
        "output":     output or None,
        "format":     fmt,
        "modules":    modules,
        "variations": variations,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RUN SCAN
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(cfg: dict):
    # Animated launch message
    console.print()
    with console.status("[bold bright_red]Initializing OdiRecon …[/bold bright_red]",
                        spinner="dots", spinner_style="bright_red"):
        time.sleep(0.8)
    console.print("  [bold bright_red]▶[/bold bright_red]  [bold white]Scan launched[/bold white]  "
                  f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print()

    scanner = OdiReconScanner(
        domain=cfg["domain"],
        threads=cfg["threads"],
        timeout=cfg["timeout"],
    )
    scanner.stats["start_time"] = time.time()

    modules  = cfg.get("modules", [k for k, _, __, ___ in ALL_MODULES])
    wordlist = load_wordlist(cfg["wordlist"]) if "dns" in modules or "http" in modules else []

    if cfg.get("variations") and wordlist:
        wordlist = generate_variations(wordlist)
        console.print(f"  [bold green][+][/bold green] Variations generated → [cyan]{len(wordlist):,}[/cyan] words")

    console.print(
        f"\n  [bold]Target:[/bold] [bright_red]{cfg['domain']}[/bright_red]  "
        f"[bold]Words:[/bold] [cyan]{len(wordlist):,}[/cyan]  "
        f"[bold]Threads:[/bold] [cyan]{cfg['threads']}[/cyan]  "
        f"[bold]Modules:[/bold] [cyan]{', '.join(modules)}[/cyan]\n"
    )

    live_hosts: list[dict] = []

    # ── DNS ───────────────────────────────────────────────────────────────────
    if "dns" in modules and wordlist:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(), console=console, transient=True
        ) as prog:
            tid = prog.add_task("[yellow]DNS bruteforce…", total=len(wordlist))
            live_hosts = scanner.run_dns_enum(wordlist, prog, tid)

    # ── HTTP Probe ────────────────────────────────────────────────────────────
    if "http" in modules:
        if live_hosts:
            live_hosts = scanner.run_http_probe(live_hosts)
        else:
            # No DNS results → try http probe on full wordlist subset (first 200)
            stub_hosts = [{"subdomain": f"{s}.{scanner.domain}", "ips": [], "cname": None}
                          for s in wordlist[:200]]
            live_hosts = scanner.run_http_probe(stub_hosts)

    # ── Port scan ─────────────────────────────────────────────────────────────
    if "ports" in modules and live_hosts:
        scanner.run_port_scan(live_hosts)

    # ── WAF ───────────────────────────────────────────────────────────────────
    if "waf" in modules and live_hosts:
        scanner.run_waf_detection(live_hosts)

    # ── Takeover ──────────────────────────────────────────────────────────────
    if "takeover" in modules and live_hosts:
        scanner.run_takeover_check(live_hosts)

    # ── SSL ───────────────────────────────────────────────────────────────────
    if "ssl" in modules and live_hosts:
        scanner.run_ssl_check(live_hosts)

    # ── Headers ───────────────────────────────────────────────────────────────
    if "headers" in modules and live_hosts:
        scanner.run_security_headers(live_hosts)

    # ── CORS ──────────────────────────────────────────────────────────────────
    if "cors" in modules and live_hosts:
        scanner.run_cors_check(live_hosts)

    # ── S3 ────────────────────────────────────────────────────────────────────
    if "s3" in modules:
        scanner.run_s3_check()

    # ── Open redirect ─────────────────────────────────────────────────────────
    if "redirect" in modules and live_hosts:
        scanner.run_open_redirect(live_hosts)

    # ── Smuggling ─────────────────────────────────────────────────────────────
    if "smuggling" in modules and live_hosts:
        scanner.run_http_smuggling(live_hosts)

    # ── Param pollution ───────────────────────────────────────────────────────
    if "pollution" in modules and live_hosts:
        scanner.run_param_pollution(live_hosts)

    scanner.stats["end_time"] = time.time()
    scanner.stats["live"]     = len(live_hosts)

    print_summary(scanner)

    if cfg.get("output") and scanner.findings:
        save_results(scanner.findings, cfg["output"], cfg.get("format", "txt"))


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="odirecon",
        description="Advanced Red Team Recon Toolkit v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python odirecon.py                                       # interactive mode
  python odirecon.py -d example.com -w wordlist.txt
  python odirecon.py -d example.com -w wordlist.txt -t 50 --timeout 10
  python odirecon.py -d example.com -w wordlist.txt -o report.html --format html
  python odirecon.py -d example.com -w wordlist.txt --modules dns,headers,cors,ssl,s3
  python odirecon.py -d example.com -w wordlist.txt --variations
        """
    )
    p.add_argument("-d", "--domain",    help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist",  help="Path to subdomain wordlist")
    p.add_argument("-t", "--threads",   type=int, default=30,
                   help="Concurrent threads (default: 30)")
    p.add_argument("--timeout",         type=int, default=5,
                   help="Request timeout in seconds (default: 5)")
    p.add_argument("-o", "--output",    help="Output file path")
    p.add_argument("--format",          choices=["txt","json","csv","html"],
                   default="json",      help="Output format (default: json)")
    p.add_argument("--modules",         default="all",
                   help="Comma-separated modules: dns,http,ports,waf,takeover,ssl,"
                        "headers,cors,s3,redirect,smuggling,pollution  (default: all)")
    p.add_argument("--variations",      action="store_true",
                   help="Generate wordlist variations")
    p.add_argument("--list-modules",    action="store_true",
                   help="List available modules and exit")
    return p


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    parser = build_parser()
    args   = parser.parse_args()

    if args.list_modules:
        t = Table(title="Available Modules", box=box.SIMPLE_HEAD, border_style="bright_red",
                  header_style="bold bright_white")
        t.add_column("#",        justify="right",  style="bold bright_red", width=4)
        t.add_column("Key",      style="bold cyan", width=12)
        t.add_column("Icon",     justify="center",  width=4)
        t.add_column("Module",   style="white",     width=30)
        t.add_column("Max Sev",  justify="center",  width=12)
        for i, (k, name, icon, sev) in enumerate(ALL_MODULES, 1):
            sev_style = _SEV_COLOR.get(sev, "white")
            t.add_row(str(i), k, icon, name, f"[{sev_style}]{sev}[/{sev_style}]")
        console.print(t)
        sys.exit(0)

    # ── Interactive mode if no domain supplied ────────────────────────────────
    if not args.domain:
        if not PROMPT_TOOLKIT:
            console.print("[red][!] prompt_toolkit not installed. "
                          "Run with -d / --domain for CLI mode.[/red]")
            parser.print_help()
            sys.exit(1)
        try:
            cfg = interactive_mode()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow][!] Aborted.[/yellow]")
            sys.exit(0)
    else:
        if not args.wordlist:
            console.print("[red][!] --wordlist is required in CLI mode.[/red]")
            parser.print_help()
            sys.exit(1)
        modules_raw = args.modules.strip().lower()
        if modules_raw == "all":
            mods = [k for k, _, __, ___ in ALL_MODULES]
        else:
            mods = [m.strip() for m in modules_raw.split(",") if m.strip()]
        cfg = {
            "domain":     args.domain,
            "wordlist":   args.wordlist,
            "threads":    args.threads,
            "timeout":    args.timeout,
            "output":     args.output,
            "format":     args.format,
            "modules":    mods,
            "variations": args.variations,
        }

    try:
        run_scan(cfg)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
