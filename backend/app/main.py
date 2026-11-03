from fastapi import FastAPI

app = FastAPI(
    title="CyberShield API",
    description="AI-Based Multi-Layer Cyber Threat Detection Framework",
    version="0.1.0"
)

@app.get("/")
def root():
    return {"message": "CyberShield API is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}