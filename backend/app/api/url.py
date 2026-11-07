
import re
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl, Field, field_validator

from app.services.url_feature_extractor import extract_url_features


router = APIRouter(
    prefix="/api/url",
    tags=["URL Analysis"]
)


class URLRequest(BaseModel):
    url: str = Field(..., max_length=2048)

    @field_validator("url", mode="before")
    @classmethod
    def normalize_url(cls, value):

        if not isinstance(value, str):
            return value

        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty.")

        # Reject malformed HTTP/HTTPS protocols
        if re.match(r"^https?:(?!//)", value, re.IGNORECASE):
            raise ValueError("Malformed URL protocol.")

        if re.match(r"^https?//", value, re.IGNORECASE):
            raise ValueError("Malformed URL protocol.")

        # Preserve valid HTTP/HTTPS URLs
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

        # Reject unsupported protocols
        elif re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        # Handle protocol-relative URLs
        elif value.startswith("//"):
            value = "https:" + value

        # Add HTTPS when protocol is missing
        else:
            value = "https://" + value

        # Validate without losing original Unicode hostname
        HttpUrl(value)

        # Add trailing slash when URL has no path
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


class URLFeatures(BaseModel):
    url_length: int
    hostname_length: int
    domain_length: int
    path_length: int

    num_subdomains: int
    subdomain_ratio: float
    max_subdomain_length: int
    domain_entropy: float
    domain_digit_count: int
    domain_hyphen_count: int

    contains_unicode: int
    non_ascii_count: int
    mixed_script: int
    contains_punycode: int

    has_https: int
    has_ip_address: int
    has_at_symbol_in_authority: int
    has_double_slash_in_path: int
    has_encoded_characters: int
    percent_encoded_count: int
    has_nonstandard_port: int
    has_fragment: int

    query_param_count: int
    query_length: int
    path_segment_count: int
    max_path_segment_length: int

    suspicious_keyword_subdomain_count: int
    suspicious_keyword_domain_count: int
    suspicious_keyword_path_count: int
    suspicious_keyword_query_count: int

    tld_length: int
    has_suspicious_tld: int
    has_url_shortener: int


class URLAnalysisResponse(BaseModel):
    status: str
    url: str
    features: URLFeatures


@router.post(
    "/analyze",
    response_model=URLAnalysisResponse
)
def analyze_url(request: URLRequest):

    url = request.url

    features = extract_url_features(url)

    return {
        "status": "success",
        "url": url,
        "features": features
    }
