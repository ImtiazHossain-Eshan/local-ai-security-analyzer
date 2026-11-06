"""
Main FastAPI Application Entrypoint for Sentinel Local AI Security Log Analyzer.
"""
import os
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database.db import db
from app.services.model_service import model_service
from app.services.analysis_service import analysis_service
from app.api.upload import router as upload_router
from app.api.analysis import router as analysis_router
from app.api.reports import router as reports_router

BASE_DIR = Path(__file__).resolve().parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    print("[+] Sentinel starting up...")
    db.init_db()
    analysis_service.start_worker()

    # Pre-warm or check local inference server
    if model_service.is_available:
        print("[+] Starting local AI inference runtime (llama.cpp)...")
        asyncio.create_task(model_service.ensure_running())
    else:
        print("[-] Local model file missing. Run scripts/download_model.py to initialize weights.")

    yield

    # Shutdown sequence
    print("[+] Sentinel shutting down. Stopping local model runtime...")
    model_service.stop_server()
    print("[+] Shutdown complete.")

app = FastAPI(
    title="Sentinel | Local AI Security Analyzer",
    description="Offline-capable local AI security log triage and multi-chunk correlation engine.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration for local access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(reports_router)

# Mount Static Assets & Frontend
static_dir = BASE_DIR / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/", include_in_schema=False)
async def serve_index():
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "Sentinel API is running. UI assets missing from app/static/index.html."}
