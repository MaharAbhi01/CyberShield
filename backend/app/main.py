from fastapi import FastAPI
from app.api.url import router as url_router

app = FastAPI(
    title="CyberShield API",
    description="AI-Based Multi-Layer Cyber Threat Detection Framework",
    version="0.1.0"
)

# Register URL Analysis API
app.include_router(url_router)


@app.get("/")
def root():
    return {"message": "CyberShield API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}