# CyberShield – URL Analysis API Documentation

**API Version:** 0.1.0  
**Feature Schema Version:** 2.0  
**Extractor Version:** 2.0  
**Framework:** FastAPI

---

## 1. Overview

The CyberShield URL Analysis API performs static feature extraction on submitted URLs to support phishing detection.

It extracts 33 numerical features related to URL structure, hostname characteristics, Unicode usage, suspicious keywords, ports, query parameters, and domain information.

**Important:** The current implementation performs feature extraction only. It does not yet return a final Benign or Phishing prediction.

The submitted URL is not visited or opened during analysis.

## 2. Base URL

Local development:

`http://127.0.0.1:8000`

## 3. Available Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | API welcome message |
| GET | `/health` | Health check |
| POST | `/api/url/analyze` | Extract URL features |
| GET | `/docs` | Interactive Swagger documentation |
| GET | `/redoc` | ReDoc documentation |

## 4. URL Analysis Endpoint

**Endpoint:** `/api/url/analyze`

**Method:** `POST`

**Content-Type:** `application/json`

### Request Body

```json
{
  "url": "https://example.com/login"
}
```

| Field | Type | Required | Constraint |
|---|---|---|---|
| url | String | Yes | Maximum 2048 characters |

### URL Normalization

The API automatically normalizes submitted URLs.

| Input | Behavior |
|---|---|
| `example.com` | Adds `https://` |
| `www.example.com` | Adds `https://` |
| `http://example.com` | Preserves HTTP |
| `https://example.com` | Preserves HTTPS |
| `//example.com` | Converts to HTTPS |
| Empty input | Rejected |
| `ftp://example.com` | Rejected |
| `https://http://example.com` | Rejected |
| `https//example.com` | Rejected |

A trailing slash is added when the URL has no path.

### Successful Response

**HTTP Status:** `200 OK`

Response structure:

```json
{
  "status": "success",
  "url": "https://example.com/login",
  "features": {
    "url_length": 0,
    "hostname_length": 0,
    "domain_length": 0,
    "path_length": 0,
    "num_subdomains": 0,
    "subdomain_ratio": 0.0,
    "max_subdomain_length": 0,
    "domain_entropy": 0.0,
    "domain_digit_count": 0,
    "domain_hyphen_count": 0,
    "contains_unicode": 0,
    "non_ascii_count": 0,
    "mixed_script": 0,
    "contains_punycode": 0,
    "has_https": 0,
    "has_ip_address": 0,
    "has_at_symbol_in_authority": 0,
    "has_double_slash_in_path": 0,
    "has_encoded_characters": 0,
    "percent_encoded_count": 0,
    "has_nonstandard_port": 0,
    "has_fragment": 0,
    "query_param_count": 0,
    "query_length": 0,
    "path_segment_count": 0,
    "max_path_segment_length": 0,
    "suspicious_keyword_subdomain_count": 0,
    "suspicious_keyword_domain_count": 0,
    "suspicious_keyword_path_count": 0,
    "suspicious_keyword_query_count": 0,
    "tld_length": 0,
    "has_suspicious_tld": 0,
    "has_url_shortener": 0
  }
}
```

**Note:** Zero values above illustrate the response structure only. Actual values are calculated from the submitted URL.

## 5. Extracted Features

The extractor generates exactly 33 features.

### A. URL and Domain Structure

| Feature | Description |
|---|---|
| `url_length` | Length of the normalized URL. |
| `hostname_length` | Length of the IDNA-normalized ASCII hostname. |
| `domain_length` | Length of the registrable domain label. |
| `path_length` | Number of characters in the URL path. |
| `num_subdomains` | Number of subdomain labels. |
| `subdomain_ratio` | Ratio of subdomain labels to total hostname labels. |
| `max_subdomain_length` | Length of the longest subdomain label. |
| `domain_entropy` | Shannon entropy of the registrable domain label. |
| `domain_digit_count` | Number of digits in the registrable domain. |
| `domain_hyphen_count` | Number of hyphens in the registrable domain. |

### B. Unicode and Hostname Characteristics

| Feature | Description |
|---|---|
| `contains_unicode` | Indicates whether the original hostname contains non-ASCII characters. |
| `non_ascii_count` | Number of non-ASCII code points in the hostname. |
| `mixed_script` | Detects alphabetic characters from multiple Unicode scripts. |
| `contains_punycode` | Detects hostname labels beginning with `xn--`. |

### C. URL Security Characteristics

| Feature | Description |
|---|---|
| `has_https` | Indicates whether HTTPS is used. |
| `has_ip_address` | Detects IPv4 or IPv6 hostnames. |
| `has_at_symbol_in_authority` | Detects an `@` symbol in the URL authority. |
| `has_double_slash_in_path` | Detects consecutive forward slashes in the path. |
| `has_encoded_characters` | Detects valid percent-encoded characters. |
| `percent_encoded_count` | Counts valid percent-encoded sequences. |
| `has_nonstandard_port` | Detects an explicitly specified non-default port. |
| `has_fragment` | Detects a non-empty URL fragment. |

### D. Query and Path Characteristics

| Feature | Description |
|---|---|
| `query_param_count` | Number of parsed query parameters. |
| `query_length` | Length of the raw query string. |
| `path_segment_count` | Number of non-empty path segments. |
| `max_path_segment_length` | Length of the longest path segment. |

### E. Suspicious Keyword Detection

| Feature | Description |
|---|---|
| `suspicious_keyword_subdomain_count` | Suspicious keywords found in subdomain labels. |
| `suspicious_keyword_domain_count` | Suspicious keywords found in the registrable domain. |
| `suspicious_keyword_path_count` | Suspicious keywords found in URL path segments. |
| `suspicious_keyword_query_count` | Suspicious keywords found in query parameter names and values. |

### F. TLD and URL Shortener Detection

| Feature | Description |
|---|---|
| `tld_length` | Length of the complete public suffix, excluding dots. |
| `has_suspicious_tld` | Detects suffixes present in the configured suspicious TLD list. |
| `has_url_shortener` | Detects configured URL-shortening services. |

## 6. Feature Conventions

### Binary Features

Binary features follow this convention:

| Value | Meaning |
|---|---|
| 0 | No |
| 1 | Yes |

### Machine Learning Labels

The project uses the following label encoding:

| Label | Classification |
|---|---|
| 0 | Benign |
| 1 | Phishing |

These labels are intended for the machine learning training and prediction pipeline.

The current API endpoint returns extracted features, not these classification labels.

## 7. Error Handling

The API uses FastAPI and Pydantic validation.

| HTTP Status | Description |
|---|---|
| 200 | Successful feature extraction |
| 422 | Invalid request or URL validation failure |
| 500 | Unexpected server-side error |

Examples of invalid input:

- Empty URL.
- Unsupported protocols such as FTP.
- Malformed HTTP/HTTPS protocols.
- Duplicate protocols.
- Invalid URL structure.
- URL exceeding the configured length limit.

Validation errors are returned using FastAPI's standard error response format.

## 8. Running the API Locally

Navigate to the backend directory:

```powershell
cd backend
```

Activate the virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Start the development server:

```powershell
python -m uvicorn app.main:app --reload
```

The API will be available at:

`http://127.0.0.1:8000`

Swagger UI:

`http://127.0.0.1:8000/docs`

ReDoc:

`http://127.0.0.1:8000/redoc`

## 9. Testing the API

Example PowerShell request:

```powershell
$body = @{
    url = "https://example.com/login"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/url/analyze" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

Run the URL feature extractor unit tests:

```powershell
cd backend
python -m unittest discover -s tests -v
```

## 10. Canonical Feature Schema

The canonical feature schema is maintained at:

`ml/url_feature_schema.json`

Important configuration:

- Schema version: `2.0`
- Extractor version: `2.0`
- Feature count: `33`
- Public Suffix List: Local pinned snapshot
- Label convention: `0 = Benign`, `1 = Phishing`

The canonical extractor is located at:

`backend/app/services/url_feature_extractor.py`

The same extractor, feature order, dependency configuration, and Public Suffix List snapshot must be used during dataset generation and model inference to maintain feature consistency.

---

**CyberShield – AI-Based Multi-Layer Cyber Threat Detection Framework**