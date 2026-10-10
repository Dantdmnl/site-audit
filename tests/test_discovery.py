from __future__ import annotations

import unittest
from unittest.mock import patch

from site_audit import discovery
from site_audit.models import ScanConfig


class DiscoveryParsingTests(unittest.TestCase):
    def test_sitemap_index_can_point_to_extensionless_urls(self):
        data = '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://example.com/maps?id=1</loc></sitemap></sitemapindex>'
        nested, pages = discovery.extract_sitemap_entries(data)
        self.assertEqual(nested, ["https://example.com/maps?id=1"])
        self.assertEqual(pages, [])

    def test_xml_document_url_is_not_recursed_as_a_sitemap(self):
        data = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/document.xml</loc></url></urlset>'
        self.assertEqual(discovery.extract_sitemap_entries(data), ([], ["https://example.com/document.xml"]))

    def test_xml_entities_are_rejected(self):
        value = '<!DOCTYPE urlset [<!ENTITY x "private">]><urlset><url><loc>&x;</loc></url></urlset>'
        self.assertEqual(discovery.extract_sitemap_entries(value), ([], []))

    def test_atom_href_and_rss_document_links_are_retained(self):
        xml = '<feed xmlns="http://www.w3.org/2005/Atom"><entry><link rel="alternate" href="https://example.com/article.html?q=1"/><link rel="self" href="https://example.com/feed-item"/></entry></feed>'
        with patch.object(discovery, "fetch_text", return_value=xml):
            result = discovery.crawl_feeds(object(), "https://example.com/", "", ScanConfig())
        self.assertEqual(result, {"https://example.com/article.html?q=1"})

    def test_document_urls_are_content_but_static_assets_are_not(self):
        for url in ("/article.html", "/document.pdf", "/page.php?id=1"):
            self.assertTrue(discovery.is_content_url(url, "https://example.com/"))
        for url in ("/image.png", "/assets/site.js", "https://foreign.example/article.html"):
            self.assertFalse(discovery.is_content_url(url, "https://example.com/"))
