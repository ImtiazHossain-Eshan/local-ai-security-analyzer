#!/usr/bin/env python3
"""
Sentinel Runner Script.
Starts the FastAPI application with Uvicorn.
"""
import sys
import uvicorn
from app.config import settings

def main():
    print("=" * 60)
    print("  SENTINEL - LOCAL AI SECURITY LOG ANALYZER")
    print(f"  Target: http://{settings.app_host}:{settings.app_port}")
    print(f"  Model: {settings.model_name} (2 CPU threads, 2048 ctx)")
    print("=" * 60)

    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=False,
        workers=1,  # Strictly single worker for model safety
        log_level="info"
    )

if __name__ == "__main__":
    main()
