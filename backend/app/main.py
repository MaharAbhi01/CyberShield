from fastapi import FastAPI
from app.api.url import router as url_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="CyberShield API",
    description="AI-Based Multi-Layer Cyber Threat Detection Framework",
    version="0.1.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register URL Analysis API
app.include_router(url_router)


@app.get("/")
def root():
    return {"message": "CyberShield API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}