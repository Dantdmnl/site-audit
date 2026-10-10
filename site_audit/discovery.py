"""Bounded same-origin sitemap, feed, API, and DNS inventories."""
from __future__ import annotations

import re
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from defusedxml.ElementTree import fromstring as parse_xml
from defusedxml.common import DefusedXmlException

from .core import EXTRACT_DOMAIN, TimeBudget
from .defaults import DISCOVER_SUBDOMAIN_PREFIXES
from .models import ScanConfig
from .network import fetch_response, fetch_text, is_content_url, is_internal, normalize_url

def extract_sitemap_entries(xml_text: str) -> tuple[list[str], list[str]]:
    try:
        root = parse_xml(xml_text)
    except (ET.ParseError, DefusedXmlException):
        return [], []
    kind = root.tag.rsplit("}", 1)[-1]
    locations = [e.text.strip() for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "loc" and e.text]
    return (locations, []) if kind == "sitemapindex" else ([], locations) if kind == "urlset" else ([], [])


def extract_sitemap_locs(xml_text: str) -> list[str]:
    nested, pages = extract_sitemap_entries(xml_text)
    return nested + pages


def crawl_sitemaps(
    session: requests.Session,
    base_url: str,
    config: ScanConfig,
    time_budget: TimeBudget | None = None,
) -> set[str]:
    queue: list[str] = []
    robots = fetch_text(session, urljoin(base_url, "robots.txt"), config)
    if robots:
        for line in robots.splitlines():
            if line.lower().startswith("sitemap:"):
                queue.append(line.split(":", 1)[1].strip())
    for fallback in ("/sitemap.xml", "/sitemap_index.xml"):
        url = urljoin(base_url, fallback)
        if url not in queue:
            queue.append(url)

    seen_maps: set[str] = set()
    urls: set[str] = set()
    while queue:
        if time_budget and time_budget.exhausted():
            break
        sm = queue.pop(0)
        if not is_internal(sm, base_url):
            continue
        sm = normalize_url(sm, base_url)
        if sm in seen_maps:
            continue
        if len(seen_maps) >= 100:
            if config.runtime:
                config.runtime.mark_partial("sitemap_limit")
            break
        seen_maps.add(sm)
        xml = fetch_text(session, sm, config)
        if not xml:
            continue
        nested, pages = extract_sitemap_entries(xml)
        for loc in nested:
            if is_internal(loc, base_url):
                queue.append(normalize_url(loc, sm))
        for loc in pages:
            if time_budget and time_budget.exhausted():
                break
            if is_content_url(loc, base_url):
                urls.add(normalize_url(loc, base_url))
    return urls


def crawl_feeds(
    session: requests.Session,
    base_url: str,
    html: str,
    config: ScanConfig,
    time_budget: TimeBudget | None = None,
) -> set[str]:
    urls: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    feed_urls = [urljoin(base_url, "feed/")]
    for tag in soup.find_all("link", href=True, type=re.compile("rss|atom", re.I)):
        href = str(tag["href"]).strip()
        if is_internal(href, base_url):
            feed_urls.append(urljoin(base_url, href))
    for feed_url in dict.fromkeys(feed_urls):
        if time_budget and time_budget.exhausted():
            break
        xml = fetch_text(session, feed_url, config)
        if not xml:
            continue
        try:
            root = parse_xml(xml)
        except (ET.ParseError, DefusedXmlException):
            continue
        for elem in root.iter():
            if time_budget and time_budget.exhausted():
                break
            if elem.tag.rsplit("}", 1)[-1] != "link" or elem.get("rel", "alternate") != "alternate":
                continue
            candidate = elem.get("href") or elem.text
            if candidate and is_content_url(candidate.strip(), base_url):
                urls.add(normalize_url(candidate.strip(), feed_url))
    return urls


def fetch_api_urls(
    session: requests.Session,
    base_url: str,
    config: ScanConfig,
    time_budget: TimeBudget | None = None,
) -> set[str]:
    urls: set[str] = set()
    probes = [
        ("wp-json/wp/v2/posts?per_page=100&_fields=link", "link"),
        ("wp-json/wp/v2/pages?per_page=100&_fields=link", "link"),
        ("api/v1/posts", "url"), ("api/v1/pages", "url"),
        ("api/v2/posts", "url"), ("api/posts", "url"),
    ]
    for endpoint, _ in probes:
        if time_budget and time_budget.exhausted():
            break
        resp, _ = fetch_response(session, urljoin(base_url, endpoint), config=config)
        if resp is None or not resp.ok:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        rows = payload if isinstance(payload, list) else payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list):
            continue
        for item in rows:
            if time_budget and time_budget.exhausted():
                break
            if isinstance(item, dict):
                for k in ("link", "url", "href", "permalink"):
                    val = item.get(k)
                    if isinstance(val, str):
                        target = val if val.startswith("http") else urljoin(base_url, val)
                        if is_content_url(target, base_url):
                            urls.add(normalize_url(target, base_url))
                        break
    return urls


def _is_ip_address(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def _base_domain(host: str) -> str:
    extracted = EXTRACT_DOMAIN(host)
    return extracted.top_domain_under_public_suffix


def discover_subdomains(
    base_url: str,
    prefixes: list[str],
    time_budget: TimeBudget | None = None,
) -> set[str]:
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if not host or _is_ip_address(host):
        return set()
    base = _base_domain(host)
    if not base:
        return set()
    scheme = parsed.scheme or "https"
    results: set[str] = set()
    for prefix in prefixes:
        if time_budget and time_budget.exhausted():
            break
        candidate = f"{prefix}.{base}"
        try:
            socket.getaddrinfo(candidate, None)
        except OSError:
            continue
        results.add(normalize_url(f"{scheme}://{candidate}/", base_url))
    return results


def discover_mode(
    session: requests.Session,
    base_url: str,
    html: str,
    config: ScanConfig,
    time_budget: TimeBudget | None = None,
    discover_subdomains_flag: bool = False,
    subdomain_prefixes: list[str] | None = None,
) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    homepage_links: set[str] = set()
    for tag in soup.find_all("a", href=True):
        href = str(tag["href"]).strip()
        if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
            if is_internal(href, base_url):
                homepage_links.add(normalize_url(href, base_url))

    sitemap_urls = crawl_sitemaps(session, base_url, config, time_budget)
    feed_urls = crawl_feeds(session, base_url, html, config, time_budget)
    api_urls = fetch_api_urls(session, base_url, config, time_budget)
    subdomain_urls: set[str] = set()
    if discover_subdomains_flag:
        prefixes = subdomain_prefixes or DISCOVER_SUBDOMAIN_PREFIXES
        subdomain_urls = discover_subdomains(base_url, prefixes, time_budget)

    all_discovered = sitemap_urls | feed_urls | api_urls | subdomain_urls
    hidden = sorted(all_discovered - homepage_links - {normalize_url(base_url, base_url)})

    print(f"Homepage internal links       : {len(homepage_links)}")
    print(f"Discovered (sitemap/feed/API) : {len(all_discovered)}")
    if discover_subdomains_flag:
        print(f"Subdomains resolved           : {len(subdomain_urls)}")
    print(f"Not linked from homepage      : {len(hidden)}\n")
    for url in hidden:
        print(url)

    if time_budget and time_budget.exhausted():
        print("\n[INFO] Time budget reached during discovery; results may be partial.")

    return {
        "homepage_internal_links": sorted(homepage_links),
        "discovered": sorted(all_discovered),
        "subdomains": sorted(subdomain_urls),
        "hidden": hidden,
    }
