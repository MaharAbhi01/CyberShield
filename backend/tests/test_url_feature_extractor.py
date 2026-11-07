import math
import unittest

from app.services.url_feature_extractor import extract_url_features


class TestURLFeatureExtractor(unittest.TestCase):

    def test_feature_count_and_order(self):
        features = extract_url_features("https://www.google.com")

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
            "has_url_shortener",
        ]

        self.assertEqual(list(features.keys()), expected_features)
        self.assertEqual(len(features), 33)

    def test_all_values_are_finite(self):
        features = extract_url_features(
            "https://example.com/path?user=test"
        )

        for value in features.values():
            self.assertTrue(math.isfinite(value))

    def test_https_default_port(self):
        features = extract_url_features("https://example.com:443")

        self.assertEqual(features["has_https"], 1)
        self.assertEqual(features["has_nonstandard_port"], 0)

    def test_nonstandard_port(self):
        features = extract_url_features("https://example.com:8443")

        self.assertEqual(features["has_nonstandard_port"], 1)

    def test_ip_address(self):
        features = extract_url_features("https://192.0.2.1/login")

        self.assertEqual(features["has_ip_address"], 1)
        self.assertEqual(features["domain_length"], 0)
        self.assertEqual(features["suspicious_keyword_path_count"], 1)

    def test_url_shortener(self):
        features = extract_url_features("https://bit.ly/abc")

        self.assertEqual(features["has_url_shortener"], 1)

    def test_suspicious_tld(self):
        features = extract_url_features("https://example.top")

        self.assertEqual(features["has_suspicious_tld"], 1)

    def test_suspicious_keywords(self):
        features = extract_url_features(
            "https://login.account-example.com/verify?password=test"
        )

        self.assertEqual(
            features["suspicious_keyword_subdomain_count"], 1
        )
        self.assertEqual(
            features["suspicious_keyword_domain_count"], 1
        )
        self.assertEqual(
            features["suspicious_keyword_path_count"], 1
        )
        self.assertEqual(
            features["suspicious_keyword_query_count"], 1
        )

    def test_unicode_hostname(self):
        features = extract_url_features("https://пример.рф")

        self.assertEqual(features["contains_unicode"], 1)
        self.assertEqual(features["mixed_script"], 0)
        self.assertGreater(features["non_ascii_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)