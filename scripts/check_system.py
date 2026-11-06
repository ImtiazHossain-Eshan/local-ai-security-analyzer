#!/usr/bin/env python3
"""
System health and readiness check script for Sentinel Local AI Security Analyzer.
Verifies system specifications, hardware constraints, dependencies, and local model status.
"""
import os
import sys
import psutil
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def check_system():
    print("=" * 60)
    print("  SENTINEL - SYSTEM & LOCAL AI PRE-FLIGHT CHECK")
    print("=" * 60)

    # 1. OS & Python
    py_version = platform.python_version()
    print(f"[+] OS: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"[+] Python Version: {py_version}")
    if sys.version_info < (3, 10):
        print("  [!] WARNING: Python 3.11+ is recommended.")

    # 2. CPU & Memory
    cpu_count = psutil.cpu_count(logical=True)
    mem = psutil.virtual_memory()
    total_ram_gb = round(mem.total / (1024 ** 3), 2)
    avail_ram_gb = round(mem.available / (1024 ** 3), 2)
    print(f"[+] CPU Logical Cores: {cpu_count} (Configured for 2 CPU threads)")
    print(f"[+] Total System RAM: {total_ram_gb} GB")
    print(f"[+] Available RAM: {avail_ram_gb} GB")

    if avail_ram_gb < 1.0:
        print("  [!] WARNING: Available RAM is less than 1.0 GB. Close memory-heavy apps.")

    # 3. Model Files
    model_file = BASE_DIR / "models" / "Qwen3.5-0.8B-Q4_K_M.gguf"
    tokenizer_file = BASE_DIR / "models" / "tokenizer" / "tokenizer.json"
    llama_server = BASE_DIR / "llama_bin" / "llama-server.exe"

    print("\n[+] Local AI Runtime Components:")
    if model_file.exists():
        size_mb = round(model_file.stat().st_size / (1024 * 1024), 2)
        print(f"  [PASS] Model: {model_file.name} ({size_mb} MB)")
    else:
        print(f"  [FAIL] Model NOT found at {model_file}. Run scripts/download_model.py")

    if tokenizer_file.exists():
        size_kb = round(tokenizer_file.stat().st_size / 1024, 2)
        print(f"  [PASS] Offline Tokenizer: {tokenizer_file.name} ({size_kb} KB)")
    else:
        print(f"  [FAIL] Tokenizer NOT found at {tokenizer_file}.")

    if llama_server.exists():
        print(f"  [PASS] llama-server Binary: {llama_server.name}")
    else:
        print(f"  [FAIL] llama-server NOT found at {llama_server}.")

    # 4. Regression Log File
    log_file = BASE_DIR / "Cultive8_Workspace_Agrigen_Server.log"
    print("\n[+] Regression Log Fixture:")
    if log_file.exists():
        size_kb = round(log_file.stat().st_size / 1024, 2)
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = sum(1 for _ in f)
        print(f"  [PASS] {log_file.name} ({size_kb} KB, {lines} lines)")
    else:
        print(f"  [INFO] {log_file.name} not in root directory.")

    print("=" * 60)

if __name__ == "__main__":
    check_system()
