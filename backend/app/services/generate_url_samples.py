import csv
from pathlib import Path

from url_feature_extractor import extract_url_features


# Sample URLs for testing the feature extractor
sample_urls = [
    "https://www.example.com/products?id=123",
    "http://example.com/login/verify?account=123",
    "http://192.168.1.1/login",
    "https://xn--80ak6aa92e.com"
]

# Locate the CyberShield project root
project_root = Path(__file__).resolve().parents[3]

output_file = project_root / "ml" / "datasets" / "url_feature_samples.csv"

# Generate feature rows
rows = []

for url in sample_urls:
    features = extract_url_features(url)
    features["label"] = ""
    rows.append(features)

# Write CSV
with open(output_file, "w", newline="", encoding="utf-8") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=list(rows[0].keys())
    )

    writer.writeheader()
    writer.writerows(rows)

print("Sample CSV generated successfully!")
print(f"Saved at: {output_file}")