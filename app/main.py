"""
WPGuard Main Application
WordPress File Integrity Scanner
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api import upload, ftp, scan, report
from app.core.config import settings
from app.core.database import init_db
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="WPGuard - WordPress File Integrity Scanner",
    description="External Python-based application to scan WordPress files for anomalies",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(upload.router, prefix="/api/v1", tags=["upload"])
app.include_router(ftp.router, prefix="/api/v1", tags=["ftp"])
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(report.router, prefix="/api/v1", tags=["report"])

# Mount static files for frontend
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

@app.on_event("startup")
async def startup_event():
    """Initialize database and required directories on startup"""
    await init_db()
    
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "WPGuard - WordPress File Integrity Scanner",
        "version": "0.1.0",
        "docs": "/docs",
        "api_base": "/api/v1"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "wpguard"}

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
