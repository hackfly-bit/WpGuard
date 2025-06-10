"""
WPGuard Main Application
WordPress File Integrity Scanner
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from app.api import upload, ftp, scan, report, scheduler, advanced_security
from app.core.config import settings
from app.core.database import init_db
from app.scheduler.scheduler import start_scheduler, stop_scheduler
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
app.include_router(scheduler.router, prefix="/api/v1", tags=["scheduler"])
app.include_router(advanced_security.router, prefix="/api/v1", tags=["advanced_security"])

# Mount static files for frontend
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

@app.on_event("startup")
async def startup_event():
    """Initialize database and required directories on startup"""
    await init_db()
    await start_scheduler()

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await stop_scheduler()

@app.get("/")
async def dashboard():
    """Serve the main dashboard"""
    try:
        with open("frontend/static/index.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Dashboard not found</h1><p>Please ensure the frontend files are properly installed.</p>",
            status_code=404
        )

@app.get("/api")
async def api_info():
    """API information endpoint"""
    return {
        "message": "WPGuard - WordPress File Integrity Scanner API",
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
