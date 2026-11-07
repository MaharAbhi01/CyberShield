import ipaddress
import math
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl
from pydantic import HttpUrl, ValidationError

import regex
import tldextract


# ============================================================
# 1. CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

PSL_PATH = PROJECT_ROOT / "ml" / "data" / "public_suffix_list.dat"

if not PSL_PATH.is_file():
    raise FileNotFoundError(
        f"Public Suffix List not found: {PSL_PATH}"
    )

# Fixed local PSL. No external network requests.
TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(PSL_PATH.as_uri(),),
    fallback_to_snapshot=False,
    include_psl_private_domains=True,
    cache_dir=None,
)


# ============================================================
# 2. FEATURE CONFIGURATION
# ============================================================

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "signon",
    "verify", "verification", "account", "update",
    "secure", "security", "banking", "password",
    "passcode", "credential", "confirm", "confirmation",
    "authenticate", "authentication", "wallet", "payment",
    "invoice", "billing", "recover", "recovery",
    "reset", "webscr", "free"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click",
    "work", "gq", "tk", "ml", "cf", "ga"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "tiny.cc", "cutt.ly", "ow.ly",
    "buff.ly", "lnkd.in", "rebrand.ly",
    "shorturl.at", "t.ly", "dub.co", "short.io",
    "rb.gy", "v.gd", "s.id", "amzn.to", "fb.me"
}

HEX_ESCAPE_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


# ============================================================
# 3. UNICODE SCRIPT DETECTION
# ============================================================

def build_script_patterns():
    """
    Build Unicode Script patterns using regex property metadata.

    Common, Inherited and Unknown are excluded.
    """

    script_aliases = regex._regex.get_properties()["SCRIPT"][1]

    ignored_values = {
        script_aliases["COMMON"],
        script_aliases["INHERITED"],
        script_aliases["UNKNOWN"],
    }

    # Choose one long alias for each unique script value.
    preferred_aliases = {}

    for alias, value in script_aliases.items():

        if value in ignored_values:
            continue

        if len(alias) > len(preferred_aliases.get(value, "")):
            preferred_aliases[value] = alias

    patterns = []

    for alias in preferred_aliases.values():

        pattern = regex.compile(
            rf"\A\p{{Script={alias}}}\Z"
        )

        patterns.append(pattern)

    return patterns


SCRIPT_PATTERNS = build_script_patterns()


def detect_mixed_script(hostname: str) -> int:
    """
    Returns 1 if alphabetic characters contain multiple
    distinct Unicode scripts, otherwise 0.
    """

    scripts = set()

    for char in hostname:

        if not char.isalpha():
            continue

        for index, pattern in enumerate(SCRIPT_PATTERNS):

            if pattern.fullmatch(char):
                scripts.add(index)
                break

        if len(scripts) >= 2:
            return 1

    return 0


# ============================================================
# 4. HELPER FUNCTIONS
# ============================================================

def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy."""

    if not value:
        return 0.0

    probabilities = [
        value.count(char) / len(value)
        for char in set(value)
    ]

    entropy = -sum(
        probability * math.log2(probability)
        for probability in probabilities
    )

    return float(entropy)

def normalize_url(value: str) -> str:
    """
    Canonical URL normalization shared by API and ML pipeline.
    """

    if not isinstance(value, str):
        raise ValueError("URL must be a string.")

    value = value.strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    # Reject malformed HTTP/HTTPS protocols.
    if re.match(r"^https?:(?!//)", value, re.IGNORECASE):
        raise ValueError("Malformed URL protocol.")

    if re.match(r"^https?//", value, re.IGNORECASE):
        raise ValueError("Malformed URL protocol.")

    # Preserve valid HTTP/HTTPS URLs.
    if re.match(r"^https?://", value, re.IGNORECASE):

        remaining = re.sub(
            r"^https?://",
            "",
            value,
            count=1,
            flags=re.IGNORECASE
        )

        if re.match(r"^https?://", remaining, re.IGNORECASE):
            raise ValueError("Duplicate URL protocol.")

    # Reject unsupported protocols.
    elif re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    # Handle protocol-relative URLs.
    elif value.startswith("//"):
        value = "https:" + value

    # Add HTTPS when protocol is missing.
    else:
        value = "https://" + value

    # Validate URL.
    try:
        HttpUrl(value)
    except ValidationError as exc:
        raise ValueError("Invalid URL.") from exc

    # Add trailing slash when URL has no path.
    parts = urlsplit(value)

    if not parts.path:
        value = urlunsplit((
            parts.scheme,
            parts.netloc,
            "/",
            parts.query,
            parts.fragment
        ))

    return value

def normalize_hostname(hostname: str) -> tuple[str, str]:
    """
    Returns:
        original_hostname: NFC-normalized Unicode hostname
        ascii_hostname: lowercase IDNA-normalized hostname
    """

    original_hostname = unicodedata.normalize(
        "NFC", hostname
    ).rstrip(".")

    try:
        ascii_hostname = (
            original_hostname.encode("idna")
            .decode("ascii")
            .lower()
        )

    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname.") from exc

    return original_hostname, ascii_hostname


def count_suspicious_keywords(components) -> int:
    """
    Counts distinct suspicious keywords.

    Each keyword is counted at most once within a component.
    Hyphens, underscores and other separators split tokens.
    """

    found_keywords = set()

    for component in components:

        tokens = re.findall(
            r"[a-z0-9]+",
            component.lower()
        )

        for keyword in SUSPICIOUS_KEYWORDS:

            keyword_tokens = keyword.split("-")

            size = len(keyword_tokens)

            for index in range(len(tokens) - size + 1):

                if tokens[index:index + size] == keyword_tokens:
                    found_keywords.add(keyword)
                    break

    return len(found_keywords)


def get_domain_information(ascii_hostname: str, is_ip: bool):
    """
    Extract PSL-based domain information.
    """

    if is_ip or ascii_hostname == "localhost":
        return None

    result = TLD_EXTRACTOR(ascii_hostname)

    if not result.domain or not result.suffix:
        return None

    return result


# ============================================================
# 5. MAIN FEATURE EXTRACTOR
# ============================================================

def extract_url_features(url: str) -> dict:

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    parsed_url = urlparse(url)

    scheme = parsed_url.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed_url.hostname:
        raise ValueError("URL must contain a valid hostname.")

    # --------------------------------------------------------
    # Hostname normalization
    # --------------------------------------------------------

    original_hostname, ascii_hostname = normalize_hostname(
        parsed_url.hostname
    )

    try:
        ipaddress.ip_address(ascii_hostname)
        is_ip = True

    except ValueError:
        is_ip = False

    # --------------------------------------------------------
    # PSL extraction
    # --------------------------------------------------------

    domain_info = get_domain_information(
        ascii_hostname,
        is_ip
    )

    if domain_info:

        subdomain = domain_info.subdomain
        domain = domain_info.domain
        suffix = domain_info.suffix

        subdomain_labels = (
            subdomain.split(".") if subdomain else []
        )

    else:

        subdomain = ""
        domain = ""
        suffix = ""
        subdomain_labels = []

    hostname_labels = (
        ascii_hostname.split(".") if ascii_hostname else []
    )

    # --------------------------------------------------------
    # Domain features
    # --------------------------------------------------------

    num_subdomains = len(subdomain_labels)

    total_hostname_labels = len(hostname_labels)

    subdomain_ratio = (
        num_subdomains / total_hostname_labels
        if domain_info and total_hostname_labels
        else 0.0
    )

    max_subdomain_length = max(
        (len(label) for label in subdomain_labels),
        default=0
    )

    domain_entropy = calculate_entropy(domain)

    domain_digit_count = sum(
        char.isdigit() for char in domain
    )

    domain_hyphen_count = domain.count("-")

    # --------------------------------------------------------
    # Unicode features
    # --------------------------------------------------------

    contains_unicode = int(
        any(ord(char) > 127 for char in original_hostname)
    )

    non_ascii_count = sum(
        ord(char) > 127 for char in original_hostname
    )

    mixed_script = detect_mixed_script(
        original_hostname
    )

    contains_punycode = int(
        any(
            label.lower().startswith("xn--")
            for label in parsed_url.hostname.rstrip(".").split(".")
        )
    )

    # --------------------------------------------------------
    # IP and authority features
    # --------------------------------------------------------

    has_ip_address = int(is_ip)

    has_at_symbol_in_authority = int(
        "@" in parsed_url.netloc
    )

    has_https = int(scheme == "https")

    # --------------------------------------------------------
    # Path features
    # --------------------------------------------------------

    path = parsed_url.path

    has_double_slash_in_path = int(
        "//" in path
    )

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    path_segment_count = len(path_segments)

    max_path_segment_length = max(
        (len(segment) for segment in path_segments),
        default=0
    )

    # --------------------------------------------------------
    # Encoding features
    # --------------------------------------------------------

    encoded_matches = HEX_ESCAPE_PATTERN.findall(url)

    percent_encoded_count = len(encoded_matches)

    has_encoded_characters = int(
        percent_encoded_count > 0
    )

    # --------------------------------------------------------
    # Port features
    # --------------------------------------------------------

    try:
        port = parsed_url.port

    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    default_port = 443 if scheme == "https" else 80

    has_nonstandard_port = int(
        port is not None and port != default_port
    )

    # --------------------------------------------------------
    # Fragment features
    # --------------------------------------------------------

    has_fragment = int(
        bool(parsed_url.fragment)
    )

    # --------------------------------------------------------
    # Query features
    # --------------------------------------------------------

    query = parsed_url.query

    query_parameters = parse_qsl(
        query,
        keep_blank_values=True,
        separator="&"
    )

    query_param_count = len(query_parameters)

    query_length = len(query)

    # --------------------------------------------------------
    # Suspicious keyword features
    # --------------------------------------------------------

    suspicious_keyword_subdomain_count = (
        count_suspicious_keywords(subdomain_labels)
    )

    suspicious_keyword_domain_count = (
        count_suspicious_keywords([domain])
    )

    suspicious_keyword_path_count = (
        count_suspicious_keywords(path_segments)
    )

    query_components = []

    for name, value in query_parameters:
        query_components.extend([name, value])

    suspicious_keyword_query_count = (
        count_suspicious_keywords(query_components)
    )

    # --------------------------------------------------------
    # TLD features
    # --------------------------------------------------------

    tld_length = len(suffix.replace(".", ""))

    has_suspicious_tld = int(
        suffix.lower() in SUSPICIOUS_TLDS
        if suffix
        else False
    )

    # --------------------------------------------------------
    # URL shortener feature
    # --------------------------------------------------------

    registrable_domain = (
        f"{domain}.{suffix}" if domain and suffix else ""
    )

    has_url_shortener = int(
        registrable_domain.lower() in URL_SHORTENERS
    )

    # ========================================================
    # 6. FINAL 33-FEATURE OUTPUT
    # ========================================================

    features = {

        "url_length": len(url),
        "hostname_length": len(ascii_hostname),
        "domain_length": len(domain),
        "path_length": len(path),

        "num_subdomains": num_subdomains,
        "subdomain_ratio": float(subdomain_ratio),
        "max_subdomain_length": max_subdomain_length,

        "domain_entropy": float(domain_entropy),
        "domain_digit_count": domain_digit_count,
        "domain_hyphen_count": domain_hyphen_count,

        "contains_unicode": contains_unicode,
        "non_ascii_count": non_ascii_count,
        "mixed_script": mixed_script,
        "contains_punycode": contains_punycode,

        "has_https": has_https,
        "has_ip_address": has_ip_address,
        "has_at_symbol_in_authority": has_at_symbol_in_authority,
        "has_double_slash_in_path": has_double_slash_in_path,

        "has_encoded_characters": has_encoded_characters,
        "percent_encoded_count": percent_encoded_count,
        "has_nonstandard_port": has_nonstandard_port,
        "has_fragment": has_fragment,

        "query_param_count": query_param_count,
        "query_length": query_length,

        "path_segment_count": path_segment_count,
        "max_path_segment_length": max_path_segment_length,

        "suspicious_keyword_subdomain_count": suspicious_keyword_subdomain_count,
        "suspicious_keyword_domain_count": suspicious_keyword_domain_count,
        "suspicious_keyword_path_count": suspicious_keyword_path_count,
        "suspicious_keyword_query_count": suspicious_keyword_query_count,

        "tld_length": tld_length,
        "has_suspicious_tld": has_suspicious_tld,
        "has_url_shortener": has_url_shortener,
    }

    return features


# ============================================================
# 7. BASIC TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://login.account-example.com/verify?password=test"

    extracted_features = extract_url_features(test_url)

    print("\nCyberShield URL Feature Extractor V2")
    print("=" * 55)

    for index, (name, value) in enumerate(
        extracted_features.items(), start=1
    ):

        print(f"{index:02}. {name}: {value}")

    print("=" * 55)
    print("Total features:", len(extracted_features))