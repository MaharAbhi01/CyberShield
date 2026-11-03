from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl, Field

from app.services.url_feature_extractor import extract_url_features


router = APIRouter(
    prefix="/api/url",
    tags=["URL Analysis"]
)


class URLRequest(BaseModel):
    url: HttpUrl = Field(
        ...,
        max_length=2048
    )


class URLFeatures(BaseModel):
    url_length: int
    hostname_length: int
    path_length: int

    num_dots: int
    num_subdomains: int
    num_hyphens: int
    num_underscores: int
    num_slashes: int
    num_questionmarks: int
    num_equals: int

    num_digits: int
    digit_ratio: float
    special_char_count: int

    contains_unicode: int
    non_ascii_count: int
    mixed_script: int
    contains_punycode: int

    suspicious_keyword_count: int

    has_https: int
    has_ip_address: int


class URLAnalysisResponse(BaseModel):
    status: str
    url: str
    features: URLFeatures


@router.post(
    "/analyze",
    response_model=URLAnalysisResponse
)
def analyze_url(request: URLRequest):

    url = str(request.url)

    features = extract_url_features(url)

    return {
        "status": "success",
        "url": url,
        "features": features
    }