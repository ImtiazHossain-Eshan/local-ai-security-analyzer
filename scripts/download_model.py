#!/usr/bin/env python3
"""
Model and runtime setup script for Sentinel.
Downloads:
1. Qwen3.5 0.8B GGUF Q4_K_M quantized model from Hugging Face
2. Model-compatible tokenizer for offline use
3. llama.cpp Windows prebuilt binary (if missing)
"""
import os
import sys
import io
import zipfile
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
TOKENIZER_DIR = MODELS_DIR / "tokenizer"
LLAMA_BIN_DIR = BASE_DIR / "llama_bin"

MODEL_FILENAME = "Qwen3.5-0.8B-Q4_K_M.gguf"
MODEL_URL = "https://huggingface.co/unsloth/Qwen3.5-0.8B-GGUF/resolve/main/Qwen3.5-0.8B-Q4_K_M.gguf"
HF_TOKENIZER_REPO = "Qwen/Qwen3.5-0.8B"
LLAMA_ZIP_URL = "https://github.com/ggml-org/llama.cpp/releases/download/b12167/llama-b12167-bin-win-cpu-x64.zip"

def report_progress(block_num, block_size, total_size):
    downloaded = block_num * block_size
    if total_size > 0:
        percent = min(100.0, (downloaded / total_size) * 100.0)
        mb_down = downloaded / (1024 * 1024)
        mb_tot = total_size / (1024 * 1024)
        sys.stdout.write(f"\r  Downloading: {mb_down:.1f} MB / {mb_tot:.1f} MB ({percent:.1f}%)")
        sys.stdout.flush()

def setup_model():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODELS_DIR / MODEL_FILENAME
    if model_path.exists() and model_path.stat().st_size > 500_000_000:
        print(f"[+] Model already exists at {model_path} ({model_path.stat().st_size / (1024*1024):.1f} MB)")
    else:
        print(f"[+] Downloading model from {MODEL_URL}...")
        urllib.request.urlretrieve(MODEL_URL, model_path, reporthook=report_progress)
        print(f"\n[+] Model downloaded successfully to {model_path}")

def setup_tokenizer():
    TOKENIZER_DIR.mkdir(parents=True, exist_ok=True)
    tokenizer_path = TOKENIZER_DIR / "tokenizer.json"
    if tokenizer_path.exists() and tokenizer_path.stat().st_size > 100_000:
        print(f"[+] Tokenizer already exists at {tokenizer_path}")
    else:
        print(f"[+] Exporting offline tokenizer from {HF_TOKENIZER_REPO}...")
        try:
            from tokenizers import Tokenizer
            tok = Tokenizer.from_pretrained(HF_TOKENIZER_REPO)
            tok.save(str(tokenizer_path))
            print(f"[+] Tokenizer saved to {tokenizer_path}")
        except Exception as e:
            print(f"[-] Error exporting tokenizer: {e}")
            raise

def setup_llama_binary():
    LLAMA_BIN_DIR.mkdir(parents=True, exist_ok=True)
    server_exe = LLAMA_BIN_DIR / "llama-server.exe"
    if server_exe.exists():
        print(f"[+] llama-server executable exists at {server_exe}")
    else:
        print(f"[+] Downloading llama.cpp release from {LLAMA_ZIP_URL}...")
        import httpx
        r = httpx.get(LLAMA_ZIP_URL, follow_redirects=True, timeout=90.0)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        z.extractall(LLAMA_BIN_DIR)
        print(f"[+] llama.cpp runtime extracted to {LLAMA_BIN_DIR}")

def main():
    print("=" * 60)
    print("  SENTINEL - LOCAL AI MODEL & RUNTIME DOWNLOADER")
    print("=" * 60)
    setup_model()
    setup_tokenizer()
    setup_llama_binary()
    print("\n[+] Local AI environment is complete and ready for offline inference.")
    print("=" * 60)

if __name__ == "__main__":
    main()
