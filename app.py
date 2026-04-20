#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║           S I T E R E C O N  v1.0                    ║
║   Web Route & Subdomain Discovery Tool               ║
╚═══════════════════════════════════════════════════════╝
"""

import sys
import argparse
import time
import json
import re
import os
import socket
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode
from collections import deque
from datetime import datetime

import requests
from bs4 import BeautifulSoup
import dns.resolver
import tldextract
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.live import Live
from rich.layout import Layout
from rich.rule import Rule
from colorama import init, Fore, Style

init(autoreset=True)
console = Console()

# ─── Wordlist bawaan untuk bruteforce subdomain ───────────────────────────────
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
    "webmail", "admin", "blog", "dev", "staging", "api", "api2",
    "app", "m", "mobile", "cdn", "static", "assets", "img", "images",
    "video", "media", "portal", "shop", "store", "test", "beta",
    "alpha", "demo", "docs", "help", "support", "forum", "wiki",
    "status", "monitor", "vpn", "remote", "ssh", "db", "database",
    "mysql", "postgres", "redis", "elastic", "search", "auth",
    "login", "sso", "ldap", "proxy", "gateway", "lb", "loadbalancer",
    "cloud", "backup", "git", "gitlab", "github", "jira", "jenkins",
    "ci", "cd", "devops", "k8s", "docker", "internal", "intranet",
    "extranet", "panel", "cpanel", "whm", "plesk", "webmin",
    "dashboard", "analytics", "tracking", "stats", "metrics",
    "monitor", "nagios", "zabbix", "grafana", "kibana", "elastic",
    "smtp2", "mail2", "imap", "pop3", "exchange", "autodiscover",
    "autoconfig", "calendar", "caldav", "carddav", "meet", "conference",
    "video", "stream", "live", "broadcast", "game", "games",
    "download", "upload", "files", "file", "secure", "ssl",
    "payment", "pay", "billing", "invoice", "account", "accounts",
    "user", "users", "profile", "customer", "clients", "partner",
    "partners", "affiliate", "affiliates", "reseller",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
}


# ─── Utility ──────────────────────────────────────────────────────────────────

def banner():
    ascii_art = r"""[bold cyan]
   _____ _ _       ____                     
  / ___/(_) /____ / __ \___  _________  ____ 
  \__ \/ / __/ _ \/ /_/ / _ \/ ___/ __ \/ __ \
 ___/ / / /_/  __/ _, _/  __/ /__/ /_/ / / / /
/____/_/\__/\___/_/ |_|\___/\___/\____/_/ /_/  v1.0
[/bold cyan][dim]
           Web Route & Subdomain Discovery Tool
[/dim]"""
    console.print(ascii_art)


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_base_domain(url: str) -> str:
    extracted = tldextract.extract(normalize_url(url))
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain


def is_same_domain(url: str, base_domain: str) -> bool:
    extracted = tldextract.extract(url)
    current_domain = f"{extracted.domain}.{extracted.suffix}"
    return current_domain == base_domain


def save_results(data: dict, filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f" SITE RECON REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        # Section Routes
        if "routes" in data:
            route_data = data["routes"]
            f.write(f"[+] TARGET: {route_data['target']}\n")
            f.write(f"[+] TOTAL ROUTES: {len(route_data['routes'])}\n\n")
            f.write("--- ROUTES DISCOVERED ---\n")
            for r in route_data["routes"]:
                f.write(f"{r}\n")
            
            if route_data.get("js_routes"):
                f.write("\n--- JS ROUTES ---\n")
                for r in route_data["js_routes"]:
                    f.write(f"{r}\n")
            f.write("\n" + "=" * 60 + "\n\n")

        # Section Subdomains
        if "subdomains" in data:
            sub_data = data["subdomains"]
            f.write(f"[+] DOMAIN: {sub_data['domain']}\n")
            f.write(f"[+] TOTAL SUBDOMAINS: {sub_data['total_found']}\n\n")
            f.write("--- ACTIVE SUBDOMAINS ---\n")
            f.write(f"{'SUBDOMAIN':<40} | {'IP ADDRESSES':<30} | {'STATUS'}\n")
            f.write("-" * 80 + "\n")
            for sub, info in sorted(sub_data["subdomains"].items()):
                ips = ", ".join(info.get("ips", []))
                status = str(info.get("status", "—"))
                f.write(f"{info.get('fqdn'):<40} | {ips:<30} | {status}\n")

    console.print(f"\n[bold green]✔[/bold green] Laporan berhasil disimpan ke: [cyan]{filename}[/cyan]")


# ─── Route Crawler ────────────────────────────────────────────────────────────

class RouteCrawler:
    def __init__(self, target: str, max_depth: int = 3, max_pages: int = 200,
                 timeout: int = 10, delay: float = 0.3, same_domain: bool = True):
        self.target = normalize_url(target)
        self.parsed = urlparse(self.target)
        self.base_host = self.parsed.netloc.split(":")[0]
        self.base_domain = get_base_domain(target)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay
        self.same_domain = same_domain
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

        self.visited: set[str] = set()
        self.routes: set[str] = set()
        self.external_links: set[str] = set()
        self.failed: list[str] = []
        self.forms: list[dict] = []
        self.js_routes: set[str] = set()

    def _fetch(self, url: str):
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return resp
        except requests.RequestException:
            return None

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> set[str]:
        links = set()
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag["href"].strip()
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"):
                continue
            links.add(full.split("#")[0])
        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[dict]:
        found = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            full_action = urljoin(page_url, action) if action else page_url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                })
            found.append({
                "url": full_action,
                "method": method,
                "inputs": inputs,
                "source": page_url,
            })
        return found

    def _extract_js_routes(self, soup: BeautifulSoup, base_url: str) -> set[str]:
        """Cari pola route di dalam script tag"""
        routes = set()
        pattern = re.compile(
            r"""(?:["'`])((/[\w\-/{}:]+){1,}(?:\?[\w=&%+\-._~:/?#\[\]@!$&'()*+,;]*)?)(?:["'`])"""
        )
        for script in soup.find_all("script"):
            if script.string:
                for match in pattern.finditer(script.string):
                    path = match.group(1)
                    if len(path) > 1 and not path.startswith("//"):
                        full = urljoin(base_url, path)
                        if is_same_domain(full, self.base_domain):
                            routes.add(path)
        return routes

    def _get_path(self, url: str) -> str:
        p = urlparse(url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return path

    def crawl(self) -> dict:
        queue: deque[tuple[str, int]] = deque([(self.target, 0)])
        page_count = 0

        # Cek sitemap & robots dulu
        self._check_robots()
        self._check_sitemap()

        with Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="bright_cyan"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Crawling[/cyan] [white]{self.target}[/white]",
                total=self.max_pages,
            )

            while queue and page_count < self.max_pages:
                url, depth = queue.popleft()

                if url in self.visited:
                    continue
                self.visited.add(url)

                if self.same_domain and not is_same_domain(url, self.base_domain):
                    self.external_links.add(url)
                    continue

                resp = self._fetch(url)
                progress.advance(task)

                if resp is None:
                    self.failed.append(url)
                    continue

                path = self._get_path(url)
                self.routes.add(path)
                page_count += 1

                progress.update(
                    task,
                    description=f"[cyan]Crawling[/cyan] [dim]{path[:60]}[/dim]",
                )

                ct = resp.headers.get("Content-Type", "")
                if "html" not in ct:
                    continue

                soup = BeautifulSoup(resp.text, "lxml")

                # Ekstrak link
                links = self._extract_links(soup, url)
                for link in links:
                    if link not in self.visited:
                        if depth < self.max_depth:
                            queue.append((link, depth + 1))
                        elif not is_same_domain(link, self.base_domain):
                            self.external_links.add(link)

                # Ekstrak form
                self.forms.extend(self._extract_forms(soup, url))

                # Ekstrak JS routes
                self.js_routes.update(self._extract_js_routes(soup, url))

                time.sleep(self.delay)

        return {
            "target": self.target,
            "base_domain": self.base_domain,
            "routes": sorted(self.routes),
            "js_routes": sorted(self.js_routes),
            "forms": self.forms,
            "external_links": sorted(self.external_links),
            "failed": self.failed,
            "total_pages_visited": page_count,
        }

    def _check_robots(self):
        """Parse robots.txt untuk mendapatkan semua disallow/allow paths"""
        url = f"{self.parsed.scheme}://{self.parsed.netloc}/robots.txt"
        resp = self._fetch(url)
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path != "/" and not path.startswith("http"):
                            self.routes.add(path)
                        elif path.startswith("http"):
                            self._check_sitemap(path)

    def _check_sitemap(self, sitemap_url: str = None):
        """Parse sitemap XML"""
        if sitemap_url is None:
            sitemap_url = f"{self.parsed.scheme}://{self.parsed.netloc}/sitemap.xml"
        resp = self._fetch(sitemap_url)
        if resp and resp.status_code == 200:
            try:
                soup = BeautifulSoup(resp.text, "lxml-xml")
                for loc in soup.find_all("loc"):
                    url = loc.text.strip()
                    if is_same_domain(url, self.base_domain):
                        path = self._get_path(url)
                        self.routes.add(path)
                # Rekursif sitemap index
                for sitemap in soup.find_all("sitemap"):
                    loc = sitemap.find("loc")
                    if loc:
                        self._check_sitemap(loc.text.strip())
            except Exception:
                pass


# ─── Subdomain Finder ─────────────────────────────────────────────────────────

class SubdomainFinder:
    def __init__(self, domain: str, wordlist: list = None,
                 threads: int = 50, timeout: int = 5,
                 use_crt: bool = True, use_dns: bool = True):
        self.domain = get_base_domain(domain)
        self.wordlist = wordlist or DEFAULT_SUBDOMAINS
        self.threads = threads
        self.timeout = timeout
        self.use_crt = use_crt
        self.use_dns = use_dns
        self.found: dict[str, dict] = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _resolve(self, subdomain: str) -> dict | None:
        fqdn = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            # Coba ambil CNAME
            try:
                cname = self.resolver.resolve(fqdn, "CNAME")
                cname_val = str(cname[0].target)
            except Exception:
                cname_val = None
            return {"fqdn": fqdn, "ips": ips, "cname": cname_val}
        except Exception:
            return None

    def _check_http(self, fqdn: str) -> dict:
        result = {"http": False, "https": False, "status": None, "title": None}
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{fqdn}",
                    timeout=self.timeout,
                    headers=HEADERS,
                    allow_redirects=True,
                )
                result[scheme] = True
                result["status"] = resp.status_code
                soup = BeautifulSoup(resp.text, "lxml")
                title = soup.find("title")
                result["title"] = title.text.strip()[:80] if title else None
                break
            except Exception:
                pass
        return result

    def _fetch_crt(self) -> set[str]:
        """Ambil subdomain dari crt.sh (dengan retry)"""
        subs = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        # Coba sampai 2 kali karena crt.sh sering timeout
        for attempt in range(2):
            try:
                resp = requests.get(url, timeout=25, headers=HEADERS)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lstrip("*.")
                            if n.endswith(self.domain) and n != self.domain:
                                sub_part = n[: -(len(self.domain) + 1)]
                                if sub_part:
                                    subs.add(sub_part)
                    return subs # Berhasil
            except Exception:
                time.sleep(1)
        return subs

    def _fetch_alienvault(self) -> set[str]:
        """Ambil subdomain dari AlienVault OTX API"""
        subs = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            resp = requests.get(url, timeout=15, headers=HEADERS)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "")
                    if hostname.endswith(self.domain) and hostname != self.domain:
                        sub_part = hostname[: -(len(self.domain) + 1)]
                        if sub_part:
                            subs.add(sub_part)
        except Exception:
            pass
        return subs

    def _fetch_hackertarget(self) -> set[str]:
        """Ambil subdomain dari HackerTarget API"""
        subs = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            resp = requests.get(url, timeout=10, headers=HEADERS)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        host = parts[0].strip()
                        if host.endswith(self.domain) and host != self.domain:
                            sub = host[: -(len(self.domain) + 1)]
                            if sub:
                                subs.add(sub)
        except Exception:
            pass
        return subs

    def find(self) -> dict:
        all_subs = set(self.wordlist)

        console.print()
        console.print(Rule("[bold cyan]SUBDOMAIN DISCOVERY[/bold cyan]", style="cyan"))

        # Kumpulkan dari sumber pasif
        with Progress(
            SpinnerColumn(style="yellow"),
            TextColumn("[bold yellow]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            if self.use_crt:
                t = progress.add_task("Mengambil data dari crt.sh...", total=None)
                crt_subs = self._fetch_crt()
                all_subs.update(crt_subs)
                progress.remove_task(t)
                console.print(
                    f"  [bold green]✔[/bold green] crt.sh → [cyan]{len(crt_subs)}[/cyan] subdomain ditemukan"
                )

            t = progress.add_task("Mengambil data dari HackerTarget...", total=None)
            ht_subs = self._fetch_hackertarget()
            all_subs.update(ht_subs)
            progress.remove_task(t)
            console.print(
                f"  [bold green]✔[/bold green] HackerTarget → [cyan]{len(ht_subs)}[/cyan] subdomain"
            )

            t = progress.add_task("Mengambil data dari AlienVault...", total=None)
            av_subs = self._fetch_alienvault()
            all_subs.update(av_subs)
            progress.remove_task(t)
            console.print(
                f"  [bold green]✔[/bold green] AlienVault → [cyan]{len(av_subs)}[/cyan] subdomain"
            )

        total = len(all_subs)
        console.print(
            f"\n  [dim]Total kandidat subdomain:[/dim] [bold white]{total}[/bold white]"
        )
        console.print()

        # DNS Brute-force paralel
        if self.use_dns:
            with Progress(
                SpinnerColumn(style="bold cyan"),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=35, style="cyan", complete_style="green"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Resolving DNS...[/cyan]", total=total
                )

                def worker(sub):
                    progress.advance(task)
                    result = self._resolve(sub)
                    if result:
                        http_info = self._check_http(result["fqdn"])
                        result.update(http_info)
                        return sub, result
                    return sub, None

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(worker, sub): sub for sub in all_subs}
                    for future in concurrent.futures.as_completed(futures):
                        sub, result = future.result()
                        if result:
                            self.found[sub] = result
                            progress.update(
                                task,
                                description=f"[cyan]Resolving[/cyan] [green]✔ {result['fqdn']}[/green]",
                            )

        return {
            "domain": self.domain,
            "subdomains": self.found,
            "total_found": len(self.found),
        }


# ─── Display ──────────────────────────────────────────────────────────────────

def display_routes(data: dict):
    console.print()
    console.print(Rule("[bold cyan]ROUTES DISCOVERED[/bold cyan]", style="cyan"))

    routes = data.get("routes", [])
    js_routes = data.get("js_routes", [])
    forms = data.get("forms", [])

    # Table routes
    if routes:
        table = Table(
            title=f"[bold]HTTP Routes[/bold] — {data['target']}",
            box=box.SIMPLE,
            border_style="bright_blue",
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("#", style="dim", width=5, justify="right")
        table.add_column("Path / Route", style="white", min_width=40)
        table.add_column("Type", style="yellow", width=12, justify="center")

        for i, route in enumerate(routes, 1):
            rtype = "Static"
            if "?" in route:
                rtype = "Query"
            elif any(x in route for x in ["{", ":", "<"]):
                rtype = "Dynamic"
            elif route in ["/", "/index", "/home"]:
                rtype = "Root"
            table.add_row(str(i), route, rtype)

        console.print(table)

    # JS Routes
    if js_routes:
        console.print()
        js_table = Table(
            title="[bold]Routes dari JavaScript[/bold]",
            box=box.SIMPLE_HEAD,
            border_style="yellow",
            header_style="bold yellow",
        )
        js_table.add_column("#", style="dim", width=5, justify="right")
        js_table.add_column("Path", style="white")

        for i, r in enumerate(js_routes, 1):
            js_table.add_row(str(i), r)
        console.print(js_table)

    # Forms
    if forms:
        console.print()
        form_table = Table(
            title="[bold]Form Endpoints[/bold]",
            box=box.SIMPLE_HEAD,
            border_style="magenta",
            header_style="bold magenta",
        )
        form_table.add_column("#", style="dim", width=4, justify="right")
        form_table.add_column("URL", style="white", min_width=35)
        form_table.add_column("Method", style="cyan", width=8, justify="center")
        form_table.add_column("Inputs", style="dim", width=6, justify="right")

        seen = set()
        for i, form in enumerate(forms, 1):
            key = (form["url"], form["method"])
            if key in seen:
                continue
            seen.add(key)
            form_table.add_row(
                str(i),
                form["url"],
                f"[bold green]{form['method']}[/bold green]"
                if form["method"] == "GET"
                else f"[bold yellow]{form['method']}[/bold yellow]",
                str(len(form["inputs"])),
            )
        console.print(form_table)

    # Summary
    console.print()
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold cyan")
    summary.add_column(style="white")
    summary.add_row("🌐 Target:", data["target"])
    summary.add_row("📄 Total Routes:", str(len(routes)))
    summary.add_row("⚡ JS Routes:", str(len(js_routes)))
    summary.add_row("📝 Forms:", str(len(set((f["url"], f["method"]) for f in forms))))
    summary.add_row("🔗 External Links:", str(len(data.get("external_links", []))))
    summary.add_row("❌ Failed:", str(len(data.get("failed", []))))
    summary.add_row("📊 Pages Visited:", str(data.get("total_pages_visited", 0)))

    console.print(Panel(summary, title="[bold]Summary[/bold]", border_style="bright_blue"))


def display_subdomains(data: dict):
    console.print()
    console.print(Rule("[bold green]SUBDOMAINS FOUND[/bold green]", style="green"))

    subdomains = data.get("subdomains", {})
    if not subdomains:
        console.print("  [yellow]Tidak ada subdomain yang ditemukan.[/yellow]")
        return

    table = Table(
        title=f"[bold]Active Subdomains[/bold] — {data['domain']}",
        box=box.SIMPLE,
        border_style="bright_green",
        header_style="bold green",
        show_lines=False,
    )
    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Subdomain (FQDN)", style="bold white", min_width=35)
    table.add_column("IP Address(es)", style="cyan", min_width=18)
    table.add_column("HTTP", style="green", width=6, justify="center")
    table.add_column("HTTPS", style="green", width=7, justify="center")
    table.add_column("Status", style="yellow", width=7, justify="center")
    table.add_column("Page Title", style="dim", min_width=25)

    for i, (sub, info) in enumerate(sorted(subdomains.items()), 1):
        ips = ", ".join(info.get("ips", []))
        http_ok = "[bold green]✔[/bold green]" if info.get("http") else "[red]✗[/red]"
        https_ok = "[bold green]✔[/bold green]" if info.get("https") else "[red]✗[/red]"
        status = str(info.get("status", "—"))
        if status.startswith("2"):
            status = f"[bold green]{status}[/bold green]"
        elif status.startswith("3"):
            status = f"[yellow]{status}[/yellow]"
        elif status.startswith(("4", "5")):
            status = f"[red]{status}[/red]"

        title = info.get("title") or "—"
        table.add_row(
            str(i),
            info.get("fqdn", f"{sub}.{data['domain']}"),
            ips,
            http_ok,
            https_ok,
            status,
            title[:40],
        )

    console.print(table)
    console.print(
        f"\n  [bold green]Total subdomain aktif:[/bold green] [bold white]{data['total_found']}[/bold white]"
    )


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="siterecon",
        description="Web Route & Subdomain Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python routefinder.py -u example.com                    # Route + Subdomain
  python routefinder.py -u example.com --routes-only      # Hanya route
  python routefinder.py -u example.com --subdomain-only   # Hanya subdomain
  python routefinder.py -u example.com -d 5 -p 300        # Crawl lebih dalam
  python routefinder.py -u example.com -w wordlist.txt    # Custom wordlist
  python routefinder.py -u example.com -o results.json    # Simpan ke file
        """,
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL atau domain (contoh: example.com)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Kedalaman crawl (default: 3)")
    parser.add_argument("-p", "--max-pages", type=int, default=200, help="Maks halaman di-crawl (default: 200)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout request dalam detik (default: 10)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay antar request dalam detik (default: 0.3)")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Jumlah thread untuk subdomain scan (default: 50)")
    parser.add_argument("-w", "--wordlist", help="Path ke file wordlist subdomain (1 subdomain per baris)")
    parser.add_argument("--no-crt", action="store_true", help="Nonaktifkan pencarian via crt.sh")
    parser.add_argument("--routes-only", action="store_true", help="Hanya lakukan route discovery")
    parser.add_argument("--subdomain-only", action="store_true", help="Hanya lakukan subdomain discovery")
    parser.add_argument("--external", action="store_true", help="Crawl link eksternal juga")
    parser.add_argument("-o", "--output", help="Simpan hasil ke file JSON")

    return parser.parse_args()


def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        console.print(f"[bold red]✗[/bold red] Wordlist tidak ditemukan: {path}")
        sys.exit(1)


def interactive_menu():
    banner()
    console.print("\n[bold yellow]--- INTERACTIVE MENU ---[/bold yellow]")
    
    target = console.input("[bold cyan]🎯 Masukkan URL/Domain Target: [/bold cyan]").strip()
    if not target:
        console.print("[red]Target tidak boleh kosong![/red]")
        return None

    console.print("\n[bold white]Pilih Mode Scan:[/bold white]")
    console.print(" [1] Full Reconstruction (Routes + Subdomains)")
    console.print(" [2] Routes Discovery Only")
    console.print(" [3] Subdomain Discovery Only")
    
    choice = console.input("\n[bold yellow]👉 Pilih (1/2/3) [default: 1]: [/bold yellow]") or "1"
    
    args = argparse.Namespace()
    args.url = target
    args.routes_only = (choice == "2")
    args.subdomain_only = (choice == "3")
    
    # Default values for interactive mode
    args.depth = 3
    args.max_pages = 200
    args.timeout = 10
    args.delay = 0.3
    args.threads = 50
    args.wordlist = None
    args.no_crt = False
    args.external = False
    args.output = None
    
    return args


def main():
    if len(sys.argv) == 1:
        args = interactive_menu()
        if not args:
            return
    else:
        banner()
        args = parse_args()

    target = normalize_url(args.url)
    domain = get_base_domain(args.url)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    console.print()
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold dim")
    info.add_column(style="bold white")
    info.add_row("🎯 Target:", target)
    info.add_row("📡 Domain:", domain)
    info.add_row("🕐 Waktu:", timestamp)
    console.print(Panel(info, border_style="dim", padding=(0, 1)))
    console.print()

    all_results = {}

    # ── Route Discovery ──────────────────────────────────────────────────────
    if not args.subdomain_only:
        console.print(Rule("[bold cyan]ROUTE DISCOVERY[/bold cyan]", style="cyan"))
        crawler = RouteCrawler(
            target=target,
            max_depth=args.depth,
            max_pages=args.max_pages,
            timeout=args.timeout,
            delay=args.delay,
            same_domain=not args.external,
        )
        route_data = crawler.crawl()
        display_routes(route_data)
        all_results["routes"] = route_data

    # ── Subdomain Discovery ──────────────────────────────────────────────────
    if not args.routes_only:
        wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_SUBDOMAINS
        finder = SubdomainFinder(
            domain=domain,
            wordlist=wordlist,
            threads=args.threads,
            timeout=args.timeout,
            use_crt=not args.no_crt,
            use_dns=True,
        )
        sub_data = finder.find()
        display_subdomains(sub_data)
        all_results["subdomains"] = sub_data

    # ── Simpan output ────────────────────────────────────────────────────────
    if args.output:
        save_results(all_results, args.output)
    else:
        output_file = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        save_results(all_results, output_file)

    console.print()
    console.print(Panel("[bold green]✔ Selesai![/bold green]", border_style="green", padding=(0, 2)))


if __name__ == "__main__":
    main()
