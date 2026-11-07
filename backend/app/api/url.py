
from fastapi import APIRouter
from pydantic import BaseModel, Field, field_validator

from app.services.url_feature_extractor import (
    extract_url_features,
    normalize_url as canonical_normalize_url
)


router = APIRouter(
    prefix="/api/url",
    tags=["URL Analysis"]
)


# ============================================================
# 1. URL REQUEST
# ============================================================

class URLRequest(BaseModel):
    url: str = Field(..., max_length=2048)

    @field_validator("url", mode="before")
    @classmethod
    def normalize_url(cls, value):
        return canonical_normalize_url(value)


# ============================================================
# 2. URL FEATURES RESPONSE
# ============================================================

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


# ============================================================
# 3. API RESPONSE
# ============================================================

class URLAnalysisResponse(BaseModel):
    status: str
    url: str
    features: URLFeatures


# ============================================================
# 4. URL ANALYSIS ENDPOINT
# ============================================================

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
