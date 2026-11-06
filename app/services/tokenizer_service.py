"""
Tokenizer service for exact token counting using the selected model's tokenizer.
Loads the local offline tokenizer for Qwen3.5.
"""
from pathlib import Path
from typing import List, Optional
from tokenizers import Tokenizer

from app.config import settings

class TokenizerService:
    def __init__(self, tokenizer_path: Optional[Path] = None):
        self.tokenizer_path = tokenizer_path or settings.tokenizer_path
        self._tokenizer: Optional[Tokenizer] = None
        self._load_tokenizer()

    def _load_tokenizer(self):
        if self.tokenizer_path.exists():
            self._tokenizer = Tokenizer.from_file(str(self.tokenizer_path))
        else:
            # Fallback to pretrained download if local file is missing
            try:
                self._tokenizer = Tokenizer.from_pretrained("Qwen/Qwen3.5-0.8B")
                self.tokenizer_path.parent.mkdir(parents=True, exist_ok=True)
                self._tokenizer.save(str(self.tokenizer_path))
            except Exception as e:
                raise RuntimeError(f"Failed to load tokenizer: {e}")

    def count_tokens(self, text: str) -> int:
        if not text:
            return 0
        encoding = self._tokenizer.encode(text)
        return len(encoding.ids)

    def encode(self, text: str) -> List[int]:
        if not text:
            return []
        return self._tokenizer.encode(text).ids

    def decode(self, token_ids: List[int]) -> str:
        if not token_ids:
            return ""
        return self._tokenizer.decode(token_ids)

    def truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate text to fit within max_tokens cleanly."""
        tokens = self.encode(text)
        if len(tokens) <= max_tokens:
            return text
        truncated_ids = tokens[:max_tokens]
        return self.decode(truncated_ids)

# Singleton tokenizer service
tokenizer_service = TokenizerService()
