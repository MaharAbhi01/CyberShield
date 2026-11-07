import math
import unittest

from app.services.url_feature_extractor import (
    extract_url_features,
    normalize_hostname,
    normalize_url
)


class TestURLFeatureExtractor(unittest.TestCase):

    # ========================================================
    # 1. BASIC FEATURE TESTS
    # ========================================================

    def test_feature_count(self):
        features = extract_url_features(
            "https://example.com"
        )

        self.assertEqual(len(features), 33)

    def test_feature_order(self):
        features = extract_url_features(
            "https://example.com"
        )

        expected_features = [
            "url_length",
            "hostname_length",
            "domain_length",
            "path_length",
            "num_subdomains",
            "subdomain_ratio",
            "max_subdomain_length",
            "domain_entropy",
            "domain_digit_count",
            "domain_hyphen_count",
            "contains_unicode",
            "non_ascii_count",
            "mixed_script",
            "contains_punycode",
            "has_https",
            "has_ip_address",
            "has_at_symbol_in_authority",
            "has_double_slash_in_path",
            "has_encoded_characters",
            "percent_encoded_count",
            "has_nonstandard_port",
            "has_fragment",
            "query_param_count",
            "query_length",
            "path_segment_count",
            "max_path_segment_length",
            "suspicious_keyword_subdomain_count",
            "suspicious_keyword_domain_count",
            "suspicious_keyword_path_count",
            "suspicious_keyword_query_count",
            "tld_length",
            "has_suspicious_tld",
            "has_url_shortener"
        ]

        self.assertEqual(
            list(features.keys()),
            expected_features
        )

    def test_finite_numeric_features(self):
        features = extract_url_features(
            "https://example.com/login"
        )

        for name, value in features.items():
            if isinstance(value, float):
                self.assertTrue(
                    math.isfinite(value),
                    f"{name} is not finite"
                )

    # ========================================================
    # 2. HTTPS AND PORT TESTS
    # ========================================================

    def test_https_detection(self):
        https_features = extract_url_features(
            "https://example.com"
        )

        http_features = extract_url_features(
            "http://example.com"
        )

        self.assertEqual(https_features["has_https"], 1)
        self.assertEqual(http_features["has_https"], 0)

    def test_ports_and_fragments(self):
        default_port = extract_url_features(
            "https://example.com:443/path"
        )

        nonstandard_port = extract_url_features(
            "https://example.com:8443/path"
        )

        http_port_on_https = extract_url_features(
            "https://example.com:80/path"
        )

        fragment = extract_url_features(
            "https://example.com/path#section"
        )

        self.assertEqual(
            default_port["has_nonstandard_port"], 0
        )

        self.assertEqual(
            nonstandard_port["has_nonstandard_port"], 1
        )

        self.assertEqual(
            http_port_on_https["has_nonstandard_port"], 1
        )

        self.assertEqual(fragment["has_fragment"], 1)

    # ========================================================
    # 3. IP ADDRESS TESTS
    # ========================================================

    def test_ipv4_and_ipv6(self):
        urls = [
            "https://192.0.2.1/login",
            "https://[2001:db8::1]/login"
        ]

        for url in urls:
            with self.subTest(url=url):
                features = extract_url_features(url)

                self.assertEqual(
                    features["has_ip_address"], 1
                )

                self.assertEqual(
                    features["domain_length"], 0
                )

                self.assertEqual(
                    features["num_subdomains"], 0
                )

    # ========================================================
    # 4. UNICODE AND PUNYCODE TESTS
    # ========================================================

    def test_cyrillic_hostname(self):
        features = extract_url_features(
            "https://пример.рф"
        )

        self.assertEqual(features["contains_unicode"], 1)
        self.assertEqual(features["mixed_script"], 0)

        self.assertGreater(
            features["non_ascii_count"], 0
        )

    def test_greek_hostname(self):
        features = extract_url_features(
            "https://παράδειγμα.ελ"
        )

        self.assertEqual(features["contains_unicode"], 1)
        self.assertEqual(features["mixed_script"], 0)

    def test_latin_hostname(self):
        features = extract_url_features(
            "https://example.com"
        )

        self.assertEqual(features["contains_unicode"], 0)
        self.assertEqual(features["non_ascii_count"], 0)
        self.assertEqual(features["mixed_script"], 0)

    def test_mixed_script_hostname(self):
        features = extract_url_features(
            "https://раypal.com"
        )

        self.assertEqual(features["contains_unicode"], 1)
        self.assertEqual(features["mixed_script"], 1)

    def test_nfc_hostname_normalization(self):
        composed, composed_ascii = normalize_hostname(
            "éxample.com"
        )

        decomposed, decomposed_ascii = normalize_hostname(
            "e\u0301xample.com"
        )

        self.assertEqual(composed, decomposed)
        self.assertEqual(composed_ascii, decomposed_ascii)
        self.assertEqual(composed, "éxample.com")

        composed_features = extract_url_features(
            "https://éxample.com"
        )

        decomposed_features = extract_url_features(
            "https://e\u0301xample.com"
        )

        self.assertEqual(
            composed_features["non_ascii_count"],
            decomposed_features["non_ascii_count"]
        )

    def test_unicode_and_punycode(self):
        unicode_features = extract_url_features(
            "https://пример.рф"
        )

        punycode_features = extract_url_features(
            "https://xn--e1afmkfd.xn--p1ai"
        )

        self.assertEqual(
            unicode_features["contains_unicode"], 1
        )

        self.assertEqual(
            unicode_features["contains_punycode"], 0
        )

        self.assertEqual(
            punycode_features["contains_unicode"], 0
        )

        self.assertEqual(
            punycode_features["contains_punycode"], 1
        )

    # ========================================================
    # 5. PUBLIC SUFFIX TESTS
    # ========================================================

    def test_multilabel_public_suffix(self):
        features = extract_url_features(
            "https://shop.example.co.uk"
        )

        self.assertEqual(features["domain_length"], 7)
        self.assertEqual(features["tld_length"], 4)
        self.assertEqual(features["num_subdomains"], 1)


    def test_suspicious_tld(self):
        features = extract_url_features(
            "https://example.top"
        )

        self.assertEqual(
            features["has_suspicious_tld"], 1
        )

    # ========================================================
    # 6. URL ENCODING AND PATH TESTS
    # ========================================================

    def test_encoded_characters(self):
        encoded_path = extract_url_features(
            "https://example.com/path%20name"
        )

        encoded_query = extract_url_features(
            "https://example.com/search?q=hello%2Fworld"
        )

        normal_url = extract_url_features(
            "https://example.com/plain"
        )

        self.assertEqual(
            encoded_path["has_encoded_characters"], 1
        )

        self.assertEqual(
            encoded_query["has_encoded_characters"], 1
        )

        self.assertEqual(
            normal_url["has_encoded_characters"], 0
        )

        self.assertEqual(
            encoded_path["percent_encoded_count"], 1
        )

        self.assertEqual(
            encoded_query["percent_encoded_count"], 1
        )

    def test_repeated_slashes(self):
        repeated = extract_url_features(
            "https://example.com/a//b"
        )

        normal = extract_url_features(
            "https://example.com/a/b"
        )

        self.assertEqual(
            repeated["has_double_slash_in_path"], 1
        )

        self.assertEqual(
            normal["has_double_slash_in_path"], 0
        )

        self.assertEqual(
            repeated["path_segment_count"], 2
        )

        self.assertEqual(
            normal["path_segment_count"], 2
        )

    # ========================================================
    # 7. QUERY PARAMETER TESTS
    # ========================================================

    def test_blank_query_parameters(self):
        features = extract_url_features(
            "https://example.com/?a=&b=2"
        )

        self.assertEqual(
            features["query_param_count"], 2
        )

        self.assertEqual(
            features["query_length"], 6
        )

    def test_semicolon_query_separator(self):
        features = extract_url_features(
            "https://example.com/?a=1;b=2"
        )

        self.assertEqual(
            features["query_param_count"], 1
        )

        self.assertEqual(
            features["query_length"], 7
        )

    # ========================================================
    # 8. SUSPICIOUS KEYWORD TESTS
    # ========================================================

    def test_repeated_suspicious_keywords(self):
        subdomain = extract_url_features(
            "https://login-login-login.example.com"
        )

        path = extract_url_features(
            "https://example.com/login/login/verify"
        )

        query = extract_url_features(
            "https://example.com/?password=test&password=admin"
        )

        self.assertEqual(
            subdomain["suspicious_keyword_subdomain_count"], 1
        )

        self.assertEqual(
            path["suspicious_keyword_path_count"], 2
        )

        self.assertEqual(
            query["suspicious_keyword_query_count"], 1
        )

    # ========================================================
    # 9. URL SHORTENER TESTS
    # ========================================================

    def test_url_shortener_detection(self):
        shorteners = [
            "https://bit.ly/abc",
            "https://tinyurl.com/test"
        ]

        for url in shorteners:
            with self.subTest(url=url):
                features = extract_url_features(url)

                self.assertEqual(
                    features["has_url_shortener"], 1
                )

        normal = extract_url_features(
            "https://example.com"
        )

        subdomain = extract_url_features(
            "https://notbit.ly.example.com"
        )

        self.assertEqual(normal["has_url_shortener"], 0)
        self.assertEqual(subdomain["has_url_shortener"], 0)

    # ========================================================
    # 10. SHARED URL NORMALIZATION TESTS
    # ========================================================

    def test_url_normalization(self):
        valid_cases = [
            ("google.com", "https://google.com/"),
            ("http://example.com", "http://example.com/"),
            ("https://github.com", "https://github.com/"),
            ("//example.com", "https://example.com/"),
        ]

        for input_url, expected_url in valid_cases:
            with self.subTest(url=input_url):
                self.assertEqual(
                    normalize_url(input_url),
                    expected_url
                )

    def test_invalid_url_normalization(self):
        invalid_urls = [
            "ftp://example.com",
            "https//example.com",
            "https://http://example.com",
            "",
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    normalize_url(url)


if __name__ == "__main__":
    unittest.main(verbosity=2)