import unicodedata
import ipaddress
from urllib.parse import urlparse

def detect_mixed_script(hostname: str):

    scripts = set()

    for char in hostname:

        if char.isalpha():
            unicode_name = unicodedata.name(char, "")
            script = unicode_name.split()[0] if unicode_name else ""

            if script:
                scripts.add(script)

    return int(len(scripts) > 1)

def extract_url_features(url: str):

    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path

    # Security Features
    has_ip_address = 0

    try:
        ipaddress.ip_address(hostname)
        has_ip_address = 1
    except ValueError:
        pass
    
    suspicious_keywords = [
    "login", "verify", "account", "update",
    "secure", "banking", "password", "signin",
    "confirm", "free"
]

    features = {
        
 
        
        # Basic URL Features
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),

        # Structural Features
        "num_dots": url.count("."),
       "num_subdomains": (
      0 if has_ip_address
      else max(0, len(hostname.split(".")) - 2)),

        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_questionmarks": url.count("?"),
        "num_equals": url.count("="),

        # Character Based Features
        "num_digits": sum(char.isdigit() for char in url),

        "digit_ratio": (
            sum(char.isdigit() for char in url) / len(url)
            if len(url) > 0 else 0.0
        ),

        "special_char_count": sum(
            not char.isalnum() for char in url
        ),
        
        # Homograph Features

       "contains_unicode": int(
      any(ord(char) > 127 for char in hostname)
           ),

       "non_ascii_count": sum(
        ord(char) > 127 for char in hostname
        ),

       "mixed_script": detect_mixed_script(hostname),

      "contains_punycode": int(
    any(
        label.lower().startswith("xn--")
        for label in hostname.split(".")
    )
),
      # Lexical Features
"suspicious_keyword_count": sum(
    keyword in url.lower()
    for keyword in suspicious_keywords
),

        # Security Features
        "has_https": int(parsed_url.scheme.lower() == "https"),
        "has_ip_address": has_ip_address

    }

    return features


if __name__ == "__main__":

    test_url = "https://"

    result = extract_url_features(test_url)

    for feature, value in result.items():
        print(f"{feature}: {value}")