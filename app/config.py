"""
Application configuration for Sentinel Local AI Security Log Analyzer.
"""
import os
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Application Server
    app_host: str = Field(default="127.0.0.1")
    app_port: int = Field(default=8000)
    debug: bool = Field(default=False)

    # Local AI Runtime
    model_name: str = Field(default="Qwen3.5-0.8B-Q4_K_M")
    model_path: Path = Field(default=BASE_DIR / "models" / "Qwen3.5-0.8B-Q4_K_M.gguf")
    tokenizer_path: Path = Field(default=BASE_DIR / "models" / "tokenizer" / "tokenizer.json")
    llama_bin_dir: Path = Field(default=BASE_DIR / "llama_bin")
    llama_server_port: int = Field(default=8085)
    cpu_threads: int = Field(default=2)

    # Strict Token Budgets (Non-negotiable constraints)
    model_context_limit: int = Field(default=2048)
    max_input_tokens: int = Field(default=1548)
    reserved_output_tokens: int = Field(default=350)
    safety_margin_tokens: int = Field(default=150)

    # Storage & Database
    database_path: Path = Field(default=BASE_DIR / "data" / "sentinel.db")
    upload_dir: Path = Field(default=BASE_DIR / "data" / "uploads")
    prompts_dir: Path = Field(default=BASE_DIR / "app" / "prompts")
    max_upload_size_mb: int = Field(default=50)

    # Hardware Safety Limits
    max_ram_usage_mb: int = Field(default=3500)

# Load settings singleton
settings = Settings()

# Ensure directories exist
settings.upload_dir.mkdir(parents=True, exist_ok=True)
settings.database_path.parent.mkdir(parents=True, exist_ok=True)
